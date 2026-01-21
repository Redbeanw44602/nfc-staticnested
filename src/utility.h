// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#pragma once

#include "types.h"

#include <chrono>
#include <ranges>

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
    std::vector<std::uint8_t> ret;
    switch (type) {
    case MifareCard::ClassicMini: {
        ret.append_range(std::views::iota(0, 20) | std::views::stride(4));
        break;
    }
    case MifareCard::Classic1K: {
        ret.append_range(std::views::iota(0, 64) | std::views::stride(4));
        break;
    }
    case MifareCard::Classic2K: {
        ret.append_range(std::views::iota(0, 128) | std::views::stride(4));
        break;
    }
    case MifareCard::Classic4K: {
        // TODO: C++26 std::views::concat
        ret.append_range(std::views::iota(0, 128) | std::views::stride(4));
        ret.append_range(std::views::iota(128, 256) | std::views::stride(16));
        break;
    }
    }
    return ret;
}

} // namespace mifare

} // namespace nfcpp
