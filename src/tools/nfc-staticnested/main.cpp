// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#include <print>

#include <argparse/argparse.hpp>
#include <cpptrace/from_current.hpp>
#include <nfcpp/nfc.hpp>

#include "pwn_host.h"

using namespace nfcpp;
using namespace nfcpp::mifare;

auto load_args(int argc, char* argv[]) {
    argparse::ArgumentParser program("nfc-staticnested", "0.1.0");

    InputArguments args;

    program.add_argument("-c", "--connstring")
        .default_value("")
        .store_into(args.connstring)
        .help("Specify the device's connstring.");
    program.add_argument("-m", "--mifare-classic")
        .default_value("1k")
        .choices("mini", "1k", "2k", "4k")
        .help("Specify the card type so that we know the sector structure.");
    program.add_argument("--force-detect-distance")
        .default_value(false)
        .implicit_value(true)
        .store_into(args.force_detect_distance)
        .help("Disable optimization for the Nt_1 = 0x009080A2 tag.");
    program.add_argument("--dump-keys")
        .store_into(args.dump_keys)
        .help("Dump all valid keys to a text file.");
    program.add_argument("-d", "--dump")
        .store_into(args.dump)
        .help("Dump the full card into a binary file.");
    program.add_argument("--no-default-keys")
        .default_value(false)
        .implicit_value(true)
        .store_into(args.no_default_keys)
        .help("Only test the keys specified by the user.");
    program.add_argument("-k", "--key")
        .append()
        .scan<'X', std::uint64_t>()
        .help("Add a key to the default key test list.");
    program.add_argument("--target-sector")
        .help("Specify the target sector; the dump function may fail.");
    program.add_argument("--target-key-type")
        .choices("a", "b")
        .help("Specify the target key type.");

    program.add_description(
        "Staticnested attack implemented in libnfc world. "
    );
    program.add_epilog(
        "Bug report: https://github.com/Redbeanw44602/nfc-staticnested/issues"
    );

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

int main(int argc, char* argv[]) CPPTRACE_TRY {
    auto args = load_args(argc, argv);

    // Start libnfc lifecycle
    NfcContext context;

    auto device = context.open_device(args.connstring);
    if (!device && args.connstring.empty()) {
        std::println("Scanning device...");
        auto connstrings = context.list_devices();
        if (connstrings.empty()) {
            throw std::runtime_error("No device found.");
        }
        for (auto i : connstrings) {
            std::println("* {}", i);
        }
        args.connstring = connstrings[0];
        std::println(
            "The first device has been selected. You can use --connstring "
            "\"{}\" to avoid repeated scanning next time.",
            args.connstring
        );
        device = context.open_device(args.connstring);
    }
    if (!device) {
        throw std::runtime_error("Failed to open device!");
    }

    std::println("NFC device opened: {}", device->get_name());

    auto initiator = device->as_initiator();

    // Enter raw mode
    device->set_property(NP_EASY_FRAMING, false);
    device->set_property(NP_HANDLE_CRC, false);
    device->set_property(NP_HANDLE_PARITY, false);

    // Run pwn host.
    PwnHost host(*initiator, args);

    host.run();

    return 0;
}
CPPTRACE_CATCH(const NfcException& e) {
    std::println("{}\n", e.what());
    cpptrace::from_current_exception().print();
    std::println("\n    [Note from the developer]\n");
    std::println(
        "Stacktrace generation doesn't necessarily mean there's a "
        "bug in the software. More often, it's just a way to help "
        "locate the problem. If you're sure there's a bug, please "
        "open an issue on GitHub."
    );
    return 1;
}
catch (const std::runtime_error& e) {
    // std::runtime_error is expected, so no stacktrace is provided.
    std::println("{}", e.what());
    return 1;
}
catch (...) {
    // It is impossible to throw other exceptions;
    // Otherwise, it would be a serious error and be handled by the operating
    // system (generating a coredump).
    throw;
}
