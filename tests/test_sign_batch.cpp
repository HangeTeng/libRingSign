#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <cassert>
#include <vector>
#include <chrono>
#include <fstream>
#include <map>
#include "libringsign/signer.h"
#include "libringsign/key_generator.h"
#include "libringsign/config_manager.h"

using namespace ring_signature_lib;
using namespace std::chrono;

// 函数返回一对毫秒级时间：{密钥生成时间，签名时间}
std::pair<long long, long long> sign_test(int participant_count) {
    auto keygen_start = high_resolution_clock::now();

    KeyGenerator keygen;
    keygen.Initialize();
    keygen.SaveConfig();

    std::string msg = "Test message";
    std::string event = "Test event";

    std::vector<Signer> signers;
    for (int i = 0; i < participant_count; ++i) {
        std::string signer_id = "signer" + std::to_string(i + 1);
        Signer signer;
        signer.Initialize(signer_id, "config/system_config.json");

        auto partial_key = signer.GeneratePartialKey();
        auto [partial_system_public_key, partial_private_key] = keygen.GenerateSignKey(signer_id, partial_key.second);
        signer.GenerateFullKey(partial_system_public_key, partial_private_key);
        assert(signer.VerifyKey() == true);

        signers.push_back(std::move(signer));
    }

    auto keygen_end = high_resolution_clock::now();
    auto keygen_duration = duration_cast<milliseconds>(keygen_end - keygen_start).count();

    // 准备 other_signer_pkc（不包括 signer1 自身）
    std::vector<std::pair<std::string, std::pair<EC_POINT*, EC_POINT*>>> other_signer_pkc;
    for (int i = 1; i < participant_count; ++i) {
        other_signer_pkc.emplace_back("signer" + std::to_string(i + 1), signers[i].GetPublicKey());
    }

    // 计时签名
    auto sign_start = high_resolution_clock::now();
    auto [A, phi, psi, T] = signers[0].Sign(msg, event, other_signer_pkc);
    auto sign_end = high_resolution_clock::now();
    auto sign_duration = duration_cast<milliseconds>(sign_end - sign_start).count();

    return {keygen_duration, sign_duration};
}

int main() {
    std::map<int, std::pair<long long, long long>> results;

    std::vector<int> test_counts = {100, 200, 300, 400, 500, 600, 700, 800, 900, 1000};

    for (int count : test_counts) {
        std::cout << "Running test for participant count: " << count << std::endl;
        auto [keygen_time, sign_time] = sign_test(count);
        results[count] = {keygen_time, sign_time};
        std::cout << "Keygen: " << keygen_time << " ms, Sign: " << sign_time << " ms\n" << std::endl;
    }

    // 输出到 Python 格式的文件 result.py
    std::ofstream ofs("result.py");
    ofs << "results = {\n";
    for (const auto& [count, times] : results) {
        ofs << "    " << count << ": {'keygen_ms': " << times.first << ", 'sign_ms': " << times.second << "},\n";
    }
    ofs << "}\n";
    ofs.close();

    std::cout << "All results written to result.py" << std::endl;

    return 0;
}
