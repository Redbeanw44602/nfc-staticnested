// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#pragma once

#include "common/mifare_initiator.h"

namespace nfcpp::mifare {

class MifareClassicDumper {
public:
    explicit MifareClassicDumper(
        MifareClassicInitiator&        initiator,
        const ISO14443ACard&           card,
        MifareCard                     type,
        std::span<const std::uint64_t> keys
    )
    : m_initiator(initiator),
      m_card(card),
      m_type(type),
      m_keys(keys) {}

    std::vector<std::uint8_t> dump();

private:
    std::uint64_t test_key_for_block(
        MifareCrypto1Cipher& cipher,
        MifareKey            key_type,
        std::uint8_t         block
    );

    std::vector<std::uint8_t>
    dump_sector(MifareCrypto1Cipher& cipher, std::uint8_t start_block);

private:
    MifareClassicInitiator& m_initiator;

    // Context
    const ISO14443ACard&           m_card;
    MifareCard                     m_type;
    std::span<const std::uint64_t> m_keys;
};

} // namespace nfcpp::mifare
