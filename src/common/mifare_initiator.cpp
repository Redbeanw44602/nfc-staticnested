// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#include <random>

#include "common/mifare_initiator.h"

#include "utility.h"

namespace nfcpp::mifare {

namespace {

using namespace util;

template <std::size_t N>
using data = NfcTransmitData<N>;

template <std::size_t N>
using data_parity = NfcTransmitDataAutoParity<N>;

template <std::size_t N>
using data_crc_parity = NfcTransmitDataAutoCRCParity<N, NfcCRC::ISO14443A>;

ISO14443ACard iso14443a_select_card(
    NfcDevice::Initiator&               initiator,
    NfcPN53xFrameBuffer&                buffer,
    const std::span<const std::uint8_t> uid  = {},
    bool                                wupa = true
) {
    ISO14443ACard ret;
    ret.atqa = initiator.transceive_bits(data(wupa ? 0x52 : 0x26), buffer, 7)
                   .expect_bytes<2>();

    constexpr auto cascade_bit   = 0x04;
    auto           cascade_level = 0x93;

    auto                        uid_known = !uid.empty();
    std::array<std::uint8_t, 4> uid_buf{};
    auto                        uid_sent_size = 0;

    while (true) {
        if (!uid_known) {
            auto anticol = initiator.transceive_bits(
                data_parity(cascade_level, 0x20),
                buffer
            );
            if (!anticol.check_bcc()) {
                std::println("!!! warning: BCC check failed!");
            }
            std::ranges::copy(anticol.get_bytes_view<4>(), uid_buf.begin());
        } else {
            if (uid.size() <= 4) {
                std::ranges::copy(uid, uid_buf.begin());
            } else {
                if (uid.size() - uid_sent_size > 4) {
                    uid_buf = {
                        0x88,
                        uid[uid_sent_size + 0],
                        uid[uid_sent_size + 1],
                        uid[uid_sent_size + 2]
                    };
                    uid_sent_size += 3;
                } else {
                    uid_buf = {
                        uid[uid_sent_size + 0],
                        uid[uid_sent_size + 1],
                        uid[uid_sent_size + 2],
                        uid[uid_sent_size + 3]
                    };
                    uid_sent_size += 4;
                }
            }
        }
        auto bcc = util::bcc(uid_buf);
        auto sak = initiator.transceive_bits(
            data_crc_parity(cascade_level, 0x70, uid_buf, bcc),
            buffer
        );
        if (!sak.check_crc<NfcCRC::ISO14443A>()) {
            std::println("!!! warning: CRC check failed!");
        }
        if (sak.get_byte<0>() & cascade_bit) {
            if (cascade_level == 0x93) cascade_level = 0x95;
            else if (cascade_level == 0x95) cascade_level = 0x97;
            else {
                throw std::runtime_error("Too many cascading levels.");
            }
            ret.uid.append_range(std::span(uid_buf).last(3));
        } else {
            ret.uid.append_range(std::span(uid_buf).first(4));
            ret.sak = sak.get_byte<0>();
            break;
        }
    }

    std::memcpy(&ret.nuid, ret.uid.data(), sizeof(ret.nuid));

    ret.nuid = util::to_big_endian(ret.nuid);

    return ret;
}

} // namespace

std::optional<ISO14443ACard>
MifareClassicInitiator::select_card(const std::span<const std::uint8_t> uid) {
    try {
        hlta();
        return iso14443a_select_card(m_initiator, m_buffer, uid);
    } catch (const NfcException& e) {
        if (e.error_code() == NfcError::RFTRANS) {
            return {};
        }
        throw;
    }
}

bool MifareClassicInitiator::auth(
    MifareCrypto1Cipher&               cipher,
    MifareKey                          key_type,
    const ISO14443ACard&               card,
    std::uint8_t                       block,
    std::uint64_t                      key,
    bool                               nested,
    detail::OptionalRef<std::uint32_t> nonce
) {
    std::uint32_t nt;

    auto cmd = static_cast<mifare_cmd>(key_type);

    if (!nested) {
        nt = m_initiator.transceive_bits(data_crc_parity(cmd, block), m_buffer)
                 .as_big_endian()
                 .expect<std::uint32_t>();
    } else {
        nt = m_initiator
                 .transceive_bits(
                     data_crc_parity(cmd, block)
                         .with_encrypt(
                             cipher,
                             [](auto&& cipher) { cipher.crypt(4); }
                         ),
                     m_buffer
                 )
                 .as_big_endian()
                 .expect<std::uint32_t>();
    }

    cipher.init(key);

    auto nuid = card.nuid;

    if (!nested) {
        cipher.word(nuid ^ nt, false);
    } else {
        nt = cipher.word(nuid ^ nt, true) ^ nt;
    }

    if (nonce) {
        nonce->get() = nt;
    }

    std::array<std::uint8_t, 4> nr;
    std::array<std::uint8_t, 4> ntt;

    static std::mt19937 random(std::random_device{}());

    for (auto i : std::views::iota(0, 4)) {
        nr[i] = random();
    }

    nt = prng_successor(nt, 32);
    for (auto i : std::views::iota(0, 4)) {
        nt     = prng_successor(nt, 8);
        ntt[i] = nt & 0xff;
    }

    auto at_r = m_initiator.transceive_bits(
        data_parity(nr, ntt).with_encrypt(
            cipher,
            [](auto&& cipher) {
                cipher.crypt_feed(4);
                cipher.crypt(4);
            }
        ),
        m_buffer
    );

    auto at = at_r.as_big_endian()
                  .as_decrypted(cipher, false, false)
                  .expect<std::uint32_t>();

    nt = prng_successor(nt, 32);

    return at == nt;
}

std::vector<std::uint8_t> MifareClassicInitiator::read(
    mifare::MifareCrypto1Cipher& cipher,
    std::uint8_t                 block
) {
    auto response = m_initiator.transceive_bits(
        data_crc_parity(0x30, block)
            .with_encrypt(cipher, [](auto&& cipher) { cipher.crypt(4); }),
        m_buffer
    );
    if (response.check_crc<NfcCRC::ISO14443A>()) {
        throw std::runtime_error(
            "CRC check of the returned block data failed."
        );
    }
    return std::ranges::to<std::vector>(response.get_bytes<16>());
}

bool MifareClassicInitiator::hlta() {
    try {
        m_initiator.transceive_bits(data_crc_parity(0x50, 0x00), m_buffer);
        return false;
    } catch (const NfcException& e) {
        if (e.error_code() == NfcError::RFTRANS) {
            return true;
        }
        throw;
    }
}

bool MifareClassicInitiator::test_key(
    mifare::MifareCrypto1Cipher& cipher,
    mifare::MifareKey            key_type,
    const ISO14443ACard&         card,
    std::uint8_t                 block,
    std::uint64_t                key
) {
    if (!select_card(card.uid)) {
        throw std::runtime_error("Tag moved out.");
    }
    try {
        if (auth(cipher, key_type, card, block, key, false)) {
            return true;
        }
    } catch (const NfcException& e) {
        if (e.error_code() != NfcError::RFTRANS) {
            throw;
        }
    }
    return false;
}

std::uint32_t MifareClassicInitiator::encrypted_nonce(
    MifareCrypto1Cipher& cipher,
    MifareKey            key_type,
    std::uint8_t         block
) {
    return m_initiator
        .transceive_bits(
            data_crc_parity(static_cast<mifare_cmd>(key_type), block)
                .with_encrypt(cipher, [](auto&& cipher) { cipher.crypt(4); }),
            m_buffer
        )
        .as_big_endian()
        .expect<std::uint32_t>();
}

std::vector<SectorKey> MifareClassicInitiator::test_default_keys(
    const ISO14443ACard&           card,
    MifareCard                     type,
    std::span<const std::uint64_t> user_keys
) {
    std::vector<std::uint64_t> default_keys = {
        0xFFFFFFFFFFFF,
        0xA0A1A2A3A4A5,
        0xD3F7D3F7D3F7,
        0x000000000000,
    };
    default_keys.append_range(user_keys);

    std::println("Testing {} default keys...", default_keys.size());

    std::vector<SectorKey> ret;
    MifareCrypto1Cipher    cipher;

    std::println("{:<6} {:<12} {:<12}", "Sector", "KeyA", "KeyB");

    for (auto block : start_block_sequence(type)) {
        std::optional<uint64_t> key_a, key_b;
        for (auto key : default_keys) {
            if (key_a && key_b) {
                break;
            }
            if (!key_a && test_key(cipher, MifareKey::A, card, block, key)) {
                key_a = key;
            }
            if (!key_b && test_key(cipher, MifareKey::B, card, block, key)) {
                key_b = key;
            }
        }
        ret.emplace_back(block_to_sector(block), key_a, key_b);
        std::println(
            "{:02d}     {:<12} {:<12}",
            block_to_sector(block),
            key_a ? std::format("{:12X}", *key_a) : "-",
            key_b ? std::format("{:12X}", *key_b) : "-"
        );
    }

    return ret;
}

std::uint64_t MifareClassicInitiator::try_get_key_b(
    MifareCrypto1Cipher& cipher,
    std::uint8_t         sector
) {
    auto block = sector_to_block(sector);

    // Convert to key block (+15 if Classic4K)
    if (block < 128) {
        block += 3;
    } else {
        block += 15;
    }

    auto data = read(cipher, block);

    std::uint64_t ret{};
    std::memcpy(&ret, data.data() + data.size() - 6, 6);

    // If KeyB is unreadable, then the value is 0
    return ret;
}

} // namespace nfcpp::mifare
