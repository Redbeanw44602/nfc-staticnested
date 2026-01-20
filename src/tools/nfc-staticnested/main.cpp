// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#include "common/mifare_initiator.h"
#include "common/static_nested.h"
#include "utility.h"

#include <argparse/argparse.hpp>

#include <nfc.hpp>

#include <print>
#include <ranges>
#include <set>
#include <unordered_set>

using namespace nfcpp;
using namespace nfcpp::mifare;
using namespace nfcpp::util;

struct ProgramArguments {
    MifareCard                  type;
    bool                        force_detect_distance;
    std::string                 dump_keys;
    std::string                 dump;
    std::vector<std::uint64_t>  user_keys;
    std::optional<std::uint8_t> target_sector;
    std::optional<MifareKey>    target_key_type;
};

auto load_args(int argc, char* argv[]) {
    argparse::ArgumentParser program("nfc-staticnested", "0.1.0");

    ProgramArguments args;

    program.add_argument("-m", "--mifare-classic")
        .default_value("1k")
        .choices("mini", "1k", "2k", "4k")
        .help("Specify the card type so that we know the sector structure.");
    program.add_argument("--force-detect-distance")
        .default_value(false)
        .implicit_value(true)
        .store_into(args.force_detect_distance)
        .help("Disable optimization for the Nt_1 = 0x009080A2 tag.");
    program.add_argument("--dumpkeys")
        .store_into(args.dump_keys)
        .help("Dump all valid keys to a text file.");
    program.add_argument("-d", "--dump")
        .store_into(args.dump)
        .help("Dump the full card into a binary file.");
    program.add_argument("-k", "--key")
        .append()
        .scan<'X', std::uint64_t>()
        .help("Add a key to the default key test list.");
    program.add_argument("--target-sector")
        .help("Specify the target sector; the dump function may fail.");
    program.add_argument("--target-key-type")
        .choices("a", "b")
        .help("Specify the target key type.");

    program.parse_args(argc, argv);

    auto type      = program.get<std::string>("-m");
    args.type      = type == "mini" ? MifareCard::ClassicMini
                   : type == "1k"   ? MifareCard::Classic1K
                   : type == "2k"   ? MifareCard::Classic2K
                   : type == "4k"   ? MifareCard::Classic4K
                                    : MifareCard::Classic1K;
    args.user_keys = program.get<std::vector<std::uint64_t>>("-k");
    if (program.is_used("--target-sector")) {
        args.target_sector = program.get<std::uint8_t>("--target-sector");
    }
    if (program.is_used("--target-key-type")) {
        auto target_key_type = program.get<std::string>("--target-key-type");
        args.target_key_type =
            target_key_type == "a" ? MifareKey::A : MifareKey::B;
    }

    for (auto key : args.user_keys) {
        if (key > (1ull << 48)) {
            throw std::runtime_error(
                "The input key must be 48 bits, for example: A1A2A3A4A5A6."
            );
        }
    }

    if (args.target_key_type.has_value() != args.target_sector.has_value()) {
        throw std::runtime_error(
            "--target-sector and --target-key-type must be provided together."
        );
    }

    return args;
}

void enter_raw_mode(NfcDevice& device) {
    device.set_property(NP_EASY_FRAMING, false);
    device.set_property(NP_HANDLE_CRC, false);
    device.set_property(NP_HANDLE_PARITY, false);
}

auto discover_tag(MifareClassicInitiator& mf_initiator) {
    auto card = mf_initiator.select_card();
    if (!card) {
        throw std::runtime_error("No tag found.");
    }

    std::println("ISO14443A-compatible tag selected:");
    std::println("    ATQA : {}", hex(card->atqa));
    std::println("    UID  : {}", hex(std::byteswap(card->nuid)));
    std::println("    SAK  : {}", hex(card->sak));

    return *card;
}

auto prepare_exploit_key(
    MifareClassicInitiator& mf_initiator,
    const ISO14443ACard&    card,
    const ProgramArguments& args
) {
    const auto test_result =
        mf_initiator.test_default_keys(card, args.type, args.user_keys);

    struct {
        SectorKey                         valid_key;
        std::unordered_set<std::uint64_t> keychain;
        std::set<std::uint8_t>            sectors_unknown_key_a;
        std::set<std::uint8_t>            sectors_unknown_key_b;
    } ret;

    auto valid_key =
        std::ranges::find_if(test_result, [](const SectorKey& skey) {
            return skey.key_a || skey.key_b;
        });
    if (valid_key == test_result.end()) {
        throw std::runtime_error(
            "At least 1 valid key is required to perform a staticnested attack."
        );
    }

    if (!args.target_sector || !args.target_key_type) {
        ret.sectors_unknown_key_a =
            test_result
            | std::views::filter([](auto& skey) { return !skey.key_a; })
            | std::views::transform([](auto& skey) { return skey.sector; })
            | std::ranges::to<std::set>();
        ret.sectors_unknown_key_b =
            test_result
            | std::views::filter([](auto& skey) { return !skey.key_b; })
            | std::views::transform([](auto& skey) { return skey.sector; })
            | std::ranges::to<std::set>();
    } else {
        if (*args.target_key_type == MifareKey::A) {
            ret.sectors_unknown_key_a.emplace(*args.target_sector);
        } else {
            ret.sectors_unknown_key_b.emplace(*args.target_sector);
        }
    }

    if (ret.sectors_unknown_key_a.empty()
        && ret.sectors_unknown_key_b.empty()) {
        throw std::runtime_error(
            "It appears there are no sectors with unknown keys."
        );
    }

    for (auto& skey : test_result) {
        if (skey.key_a) ret.keychain.emplace(*skey.key_a);
        if (skey.key_b) ret.keychain.emplace(*skey.key_b);
    }

    ret.valid_key = *valid_key;
    std::println(
        "Using key {} from sector {} to exploit...",
        valid_key->key_a ? "A" : "B",
        valid_key->sector
    );

    return ret;
}

auto try_read_key_b(
    MifareClassicInitiator& mf_initiator,
    const ISO14443ACard&    card,
    std::uint64_t           key_a,
    std::uint8_t            sector
) {
    MifareCrypto1Cipher cipher;
    if (!mf_initiator.select_card(card.uid)) {
        throw std::runtime_error("Tag moved out.");
    }
    mf_initiator.auth(
        cipher,
        MifareKey::A,
        card,
        sector_to_block(sector),
        key_a,
        false
    );
    return mf_initiator.try_get_key_b(cipher, sector);
}

void retry_unknown_key_sectors(
    MifareClassicInitiator& mf_initiator,
    const ISO14443ACard&    card,
    std::set<std::uint8_t>& sectors_a,
    std::set<std::uint8_t>& sectors_b,
    std::uint64_t           key
) {
    MifareCrypto1Cipher cipher;
    auto impl = [&](std::set<std::uint8_t>& sectors, MifareKey key_type) {
        for (auto it = sectors.begin(); it != sectors.end();) {
            if (mf_initiator.test_key(
                    cipher,
                    key_type,
                    card,
                    sector_to_block(*it),
                    key
                )) {
                std::println(
                    "This key is also Key{} of sector {}.",
                    key_type == MifareKey::A ? "A" : "B",
                    *it
                );
                it = sectors.erase(it);
            } else {
                it++;
            }
        }
    };
    impl(sectors_a, MifareKey::A);
    impl(sectors_b, MifareKey::B);
}

int main(int argc, char* argv[]) try {

    // Load arguments
    auto args = load_args(argc, argv);

    // Start libnfc lifecycle
    NfcContext context;

    auto device = context.open_device();
    std::println("NFC device opened: {}", device->get_name());

    auto initiator = device->as_initiator();

    MifareClassicInitiator mf_initiator(*initiator);
    enter_raw_mode(*device);

    auto card = discover_tag(mf_initiator);

    // Perform attack (with args)
    auto prepared = prepare_exploit_key(mf_initiator, card, args);

    auto perform_attack = [&](std::uint8_t sector, MifareKey key_type) {
        std::println("Attacking sector {}...", sector);
        auto result = static_nested::execute(
            mf_initiator,
            card,
            sector_to_block(prepared.valid_key.sector),
            prepared.valid_key.key_a ? MifareKey::A : MifareKey::B,
            prepared.valid_key.key_a ? *prepared.valid_key.key_a
                                     : *prepared.valid_key.key_b,
            sector_to_block(sector),
            key_type,
            args.force_detect_distance
        );
        if (!result.success) {
            throw std::runtime_error("\r\033[2KNo valid key found.");
        }
        std::println(
            "\r\033[2KKey{} found, is {:012X}. ({} keys tested)",
            key_type == MifareKey::A ? "A" : "B",
            result.key,
            result.tested_key_count
        );
        auto& wait_to_erase = key_type == MifareKey::A
                                ? prepared.sectors_unknown_key_a
                                : prepared.sectors_unknown_key_b;
        wait_to_erase.erase(sector);
        retry_unknown_key_sectors(
            mf_initiator,
            card,
            prepared.sectors_unknown_key_a,
            prepared.sectors_unknown_key_b,
            result.key
        );
        if (key_type == MifareKey::A
            && prepared.sectors_unknown_key_b.contains(sector)) {
            auto key_b = try_read_key_b(mf_initiator, card, result.key, sector);
            std::println("KeyB read successfully (using KeyA).");
            retry_unknown_key_sectors(
                mf_initiator,
                card,
                prepared.sectors_unknown_key_a,
                prepared.sectors_unknown_key_b,
                key_b
            );
            prepared.keychain.emplace(key_b);
        }
        prepared.keychain.emplace(result.key);
    };

    while (!prepared.sectors_unknown_key_a.empty()) {
        perform_attack(*prepared.sectors_unknown_key_a.begin(), MifareKey::A);
    }
    while (!prepared.sectors_unknown_key_b.empty()) {
        perform_attack(*prepared.sectors_unknown_key_b.begin(), MifareKey::B);
    }

    std::println("Key chain:");
    for (const auto key : prepared.keychain) {
        std::println("* {:012X}", key);
    }

    return 0;
} catch (const std::runtime_error& e) {
    std::println("{}", e.what());
    return 1;
}