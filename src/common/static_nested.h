// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#pragma once

#include "common/mifare_initiator.h"

#include "types.h"

namespace nfcpp::static_nested {

StaticNestedResult execute(
    mifare::MifareClassicInitiator& mf_initiator,
    const ISO14443ACard&            card,
    std::uint8_t                    block,
    mifare::MifareKey               key_type,
    std::uint64_t                   key,
    std::uint8_t                    target_block,
    mifare::MifareKey               target_key_type,
    bool                            force_detect_distance = false
);

} // namespace nfcpp::static_nested
