// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#pragma once

#include <nfcpp/nfc.hpp>

#include "types.h"

namespace nfcpp::mifare {

class MifareClassicInitiator {
public:
    explicit MifareClassicInitiator(NfcDevice::Initiator& initiator)
    : m_initiator(initiator) {}

    std::optional<ISO14443ACard>
    select_card(const std::span<const std::uint8_t> uid = {});

    bool auth(
        mifare::MifareCrypto1Cipher&       cipher,
        mifare::MifareKey                  key_type,
        const ISO14443ACard&               card,
        std::uint8_t                       block,
        std::uint64_t                      key,
        bool                               nested,
        detail::OptionalRef<std::uint32_t> nonce = std::nullopt
    );

    std::vector<std::uint8_t>
    read(mifare::MifareCrypto1Cipher& cipher, std::uint8_t block);

    bool hlta();

    bool test_key(
        mifare::MifareCrypto1Cipher& cipher,
        mifare::MifareKey            key_type,
        const ISO14443ACard&         card,
        std::uint8_t                 block,
        std::uint64_t                key
    );

    std::uint32_t encrypted_nonce(
        mifare::MifareCrypto1Cipher& cipher,
        mifare::MifareKey            key_type,
        std::uint8_t                 block
    );

    std::vector<SectorKey> test_default_keys(
        const ISO14443ACard&           card,
        MifareCard                     type,
        std::span<const std::uint64_t> user_keys       = {},
        bool                           no_default_keys = false
    );

    std::uint64_t
    try_get_key_b(mifare::MifareCrypto1Cipher& cipher, std::uint8_t sector);

private:
    NfcDevice::Initiator& m_initiator;
    NfcPN53xFrameBuffer   m_buffer;
};

} // namespace nfcpp::mifare
