// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#include "common/mifare_dumper.h"

#include "utility.h"

namespace nfcpp::mifare {

namespace {

using namespace util;

class AccessBits {
public:
    explicit AccessBits(std::span<const uint8_t, 3> bits) {
        c1 = (bits[1] >> 4) & 0xF;
        c2 = (bits[2] & 0xF);
        c3 = (bits[2] >> 4) & 0xF;

        uint8_t not_c1 = (bits[0] & 0xF);
        uint8_t not_c2 = (bits[0] >> 4) & 0xF;
        uint8_t not_c3 = (bits[1] & 0xF);

        chksum = c1 == (~not_c1 & 0xF) && c2 == (~not_c2 & 0xF)
              && c3 == (~not_c3 & 0xF);
    }

    bool checksum() const { return chksum; }

    int mode(std::uint8_t group) const {
        auto bc1 = (c1 >> group) & 1;
        auto bc2 = (c2 >> group) & 1;
        auto bc3 = (c3 >> group) & 1;
        return (bc1 << 2) | (bc2 << 1) | bc3;
    }

    // Group = 0, 1, 2
    // Classic4K tag may have 5 blocks in each group (Large sector)
    std::optional<MifareKey> read(std::uint8_t group) const {
        switch (mode(group)) {
        // Both, return KeyA anyway.
        case 0b000:
        case 0b010:
        case 0b100:
        case 0b110:
        case 0b001:
            return MifareKey::A;
        // KeyB
        case 0b011:
        case 0b101:
        // Dead
        case 0b111:
            break;
        }
        return std::nullopt;
    }

    bool read_key_b() const {
        switch (mode(3)) {
            // KeyA
        case 0b000:
        case 0b010:
        case 0b001:
            return true;
            // None
        case 0b100:
        case 0b110:
        case 0b011:
        case 0b101:
        case 0b111:
        default:
            return false;
        }
    }

private:
    std::uint8_t c1, c2, c3;
    bool         chksum;
};

} // namespace

std::vector<std::uint8_t> MifareClassicDumper::dump() {
    std::vector<std::uint8_t> ret;
    MifareCrypto1Cipher       cipher;

    for (auto start_block : start_block_sequence(m_type)) {
        ret.append_range(dump_sector(cipher, start_block));
    }

    return ret;
}

std::uint64_t MifareClassicDumper::test_key_for_block(
    MifareCrypto1Cipher& cipher,
    MifareKey            key_type,
    std::uint8_t         block
) {
    for (auto key : m_keys) {
        if (!m_initiator.select_card(m_card.uid)) {
            throw std::runtime_error("Tag moved out.");
        }
        if (m_initiator.test_key(cipher, key_type, m_card, block, key)) {
            return key;
        }
    }
    throw std::runtime_error(
        std::format("Can't authenticate block {}!", block)
    );
}

std::vector<std::uint8_t> MifareClassicDumper::dump_sector(
    MifareCrypto1Cipher& cipher,
    std::uint8_t         start_block
) {
    const std::uint8_t data_blocks   = start_block < 128 ? 3 : 15;
    const std::uint8_t trailer_block = start_block + data_blocks;
    const auto         sector_size   = start_block < 128 ? 64 : 256;

    std::vector<std::uint8_t> ret(sector_size);
    auto                      ret_write_ptr = 0;

    auto key_a        = test_key_for_block(cipher, MifareKey::A, trailer_block);
    auto trailer_data = m_initiator.read(cipher, trailer_block);
    auto trailer_span = std::span(trailer_data);

    auto perm = AccessBits(trailer_span.subspan<6, 3>());
    if (!perm.checksum()) {
        std::println(
            "!!! warning: sector {} has invalid access bits.",
            block_to_sector(start_block)
        );
        return ret;
    }

    // KeyB is always available for READ.
    auto key_b = test_key_for_block(cipher, MifareKey::B, trailer_block);

    for (auto index : std::views::iota(0u, data_blocks)) {
        const auto group = data_blocks == 15 ? data_blocks / 5 : index;
        const auto block = start_block + index;
        if (!perm.read(group)) {
            std::println(
                "!!! warning: unable to read block {}. (permission denied)",
                block
            );
            continue;
        }
        auto data = m_initiator.read(cipher, block);
        std::ranges::copy(data, ret.begin() + ret_write_ptr);
        std::println("read block {:02} - {}", block, hex(data));
        ret_write_ptr += data.size();
    }

    // Construct real trailer block
    std::array<std::uint8_t, 6> key_a_bytes, key_b_bytes;
    std::memcpy(key_a_bytes.data(), &key_a, 6);
    std::memcpy(key_b_bytes.data(), &key_b, 6);
    std::ranges::reverse(key_a_bytes);
    std::ranges::reverse(key_b_bytes);

    auto real_trailer_block =
        concat_bytes(key_a_bytes, trailer_span.subspan<6, 4>(), key_b_bytes);
    std::ranges::copy(real_trailer_block, ret.begin() + ret_write_ptr);
    std::println(
        "read block {:02} - {}",
        trailer_block,
        hex(real_trailer_block)
    );

    return ret;
}

} // namespace nfcpp::mifare
