// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>

namespace nfcpp {

namespace mifare {

enum class MifareKey {
    A = 0x60,
    B = 0x61,
};

enum class MifareCard {
    NotSpecified,
    ClassicMini,
    Classic1K,
    Classic2K,
    Classic4K,
};

} // namespace mifare

struct ISO14443ACard {
    std::array<std::uint8_t, 2> atqa;
    std::vector<std::uint8_t>   uid;
    std::uint32_t               nuid;
    std::uint8_t                sak;
};

struct EncryptedNonce {
    std::uint32_t nonce, keystream;
};

struct SectorKey {
    std::uint8_t                 sector;
    std::optional<std::uint64_t> key_a;
    std::optional<std::uint64_t> key_b;
};

struct StaticNestedResult {
    bool                 success;
    std::uint64_t        key;
    std::chrono::seconds time_past;
    std::size_t          tested_key_count;
};

} // namespace nfcpp