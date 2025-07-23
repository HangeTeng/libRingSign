#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <cassert>
#include "libringsign/key_generator.h"
#include "libringsign/signer.h"
#include "libringsign/config_manager.h"

using namespace ring_signature_lib;

// 辅助函数：打印 BIGNUM 内容
void print_bignum(const std::string& label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    std::cout << label << ": " << bn_str << std::endl;
    OPENSSL_free(bn_str);
}

// 辅助函数：打印 EC_POINT 内容
void print_ec_point(const std::string& label, const EC_GROUP* group, const EC_POINT* point) {
    char* point_str = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    std::cout << label << ": " << point_str << std::endl;
    OPENSSL_free(point_str);
}

void keygen_test() {
    // 创建 KeyGenerator 实例并初始化
    KeyGenerator keygen;
    keygen.Initialize(); // 使用默认 seed
    keygen.SaveConfig(); // 保存配置和系统密钥

    // 创建 Signer 实例并初始化
    Signer signer;
    std::string signer_id = "signer1";
    signer.Initialize(signer_id, DEFAULT_CONFIG_PATH);

    // 生成 Signer 的部分密钥
    auto partial_key = signer.GeneratePartialKey();
    print_ec_point("Partial Public Key (X_i)", signer.GetGroup(), partial_key.second);

    // 使用 KeyGenerator 生成完整密钥所需的签名密钥
    auto [partial_system_public_key, partial_private_key] = keygen.GenerateSignKey(signer_id, partial_key.second);

    // 使用 Signer 生成完整密钥
    signer.GenerateFullKey(partial_system_public_key, partial_private_key);
    print_ec_point("Full Public Key (Y_i)", signer.GetGroup(), signer.GetPublicKey().second);

    // 验证 Signer 密钥的正确性
    assert(signer.VerifyKey() == true);
    std::cout << "Signer full key verification passed." << std::endl;

    // 测试保存和加载 Signer 的密钥
    signer.SaveConfig();

    // 创建新的 Signer 实例，并从文件中加载密钥
    Signer signer_loaded;
    signer_loaded.LoadConfig(DEFAULT_CONFIG_PATH, DEFAULT_SIGN_KEY_PATH);

    // 打印并对比 Signer 和 Signer_Loaded 的所有参数
    std::cout << "Signer parameters:" << std::endl;
    std::cout << signer.GetParametersAsString() << std::endl;

    std::cout << "Signer_Loaded parameters:" << std::endl;
    std::cout << signer_loaded.GetParametersAsString() << std::endl;

    // 比较所有参数，包括 Hash 的 key 和 type
    assert(signer.GetParametersAsString() == signer_loaded.GetParametersAsString());
    std::cout << "All parameters in Signer and Signer_Loaded are identical." << std::endl;

    // 验证 Signer_Loaded 密钥的正确性
    assert(signer_loaded.VerifyKey() == true);
    std::cout << "Signer_Loaded full key verification passed." << std::endl;
}

int main() {
    keygen_test();
    std::cout << "All tests passed!" << std::endl;
    return 0;
}
