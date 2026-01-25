// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#pragma once

#include "types.h"

#include <chrono>

namespace nfcpp {

namespace util {

constexpr auto format_duration(auto duration) {
    std::chrono::hh_mm_ss split_time{abs(duration)};
    std::string           ret;

    if (split_time.hours().count() > 0)
        ret += std::format("{} hr, ", split_time.hours().count());
    if (split_time.minutes().count() > 0 || !ret.empty())
        ret += std::format("{} min, ", split_time.minutes().count());
    ret += std::format("{} sec", split_time.seconds().count());

    return ret;
};

} // namespace util

namespace mifare {

constexpr std::uint8_t sector_to_block(std::uint8_t sector) {
    if (sector < 32) {
        return sector * 4;
    } else {
        return 128 + (sector - 32) * 16;
    }
}

constexpr std::uint8_t block_to_sector(std::uint8_t block) {
    if (block < 128) {
        return block / 4;
    } else {
        return 32 + (block - 128) / 16;
    }
}

constexpr auto start_block_sequence(MifareCard type) {
    // TODO: C++26 std::views::concat
    // TODO: Libc++ does not yet support C++23 std::views::stride
    std::vector<std::uint8_t> ret;
    switch (type) {
    case MifareCard::ClassicMini: {
        for (std::uint8_t i = 0; i < 20; i += 4) {
            ret.emplace_back(i);
        }
        break;
    }
    case MifareCard::Classic1K: {
        for (std::uint8_t i = 0; i < 64; i += 4) {
            ret.emplace_back(i);
        }
        break;
    }
    case MifareCard::Classic2K: {
        for (std::uint8_t i = 0; i < 128; i += 4) {
            ret.emplace_back(i);
        }
        break;
    }
    case MifareCard::Classic4K: {
        for (std::uint8_t i = 0; i < 128; i += 4) {
            ret.emplace_back(i);
        }
        for (int i = 128; i < 256; i += 16) {
            ret.emplace_back(i);
        }
        break;
    }
    default:
        throw std::invalid_argument("Unreachable.");
    }
    return ret;
}

} // namespace mifare

} // namespace nfcpp
