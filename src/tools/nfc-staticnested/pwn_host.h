// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#pragma once

#include <set>

#include <nfcpp/nfc.hpp>

#include "common/mifare_initiator.h"
#include "types.h"

namespace nfcpp {

struct InputArguments {
    std::string                      connstring;
    mifare::MifareCard               type;
    bool                             force_detect_distance;
    std::string                      dump_keys;
    std::string                      dump;
    bool                             no_default_keys;
    std::vector<std::uint64_t>       user_keys;
    std::optional<std::uint8_t>      target_sector;
    std::optional<mifare::MifareKey> target_key_type;
};

class PwnHost {
public:
    PwnHost(NfcDevice::Initiator& initiator, const InputArguments& args)
    : m_initiator(initiator),
      m_args(args) {}

    void run();

private:
    void discover_tag();

    void prepare();

    void test_static_nonce();

    bool check_fm11rf08s_backdoor();

    void perform(std::uint8_t target_sector, mifare::MifareKey target_key_type);

    void on_new_key(std::uint64_t key);

    void on_key_a_found(std::uint8_t sector, std::uint64_t key);

    std::optional<std::uint64_t>
    try_read_key_b(std::uint64_t key_a, std::uint8_t sector);

    void dump_keys();

    void dump();

    bool no_unknown_keys() const {
        return m_sectors_unknown_key_a.empty()
            && m_sectors_unknown_key_b.empty();
    }

private:
    // Input
    mifare::MifareClassicInitiator m_initiator;
    ISO14443ACard                  m_card;
    InputArguments const&          m_args;

    // Context
    struct {
        mifare::MifareKey type;
        std::uint64_t     key;
        std::uint8_t      block;
    } m_valid_key;
    std::set<std::uint64_t> m_keychain;
    std::set<std::uint8_t>  m_sectors_unknown_key_a;
    std::set<std::uint8_t>  m_sectors_unknown_key_b;
};

} // namespace nfcpp
