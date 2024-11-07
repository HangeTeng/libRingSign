#include "key_generator.h"
#include <iostream>
#include <cassert>
#include <openssl/bn.h>
#include <openssl/ec.h>

namespace ring_signature_lib {

void PrintConfig(const KeyGenerator& kg) {
    std::cout << "Curve NID: " << kg.GetCurveNid() << std::endl;
    std::cout << "Hash Type: " << kg.GetHashType() << std::endl;

    // 打印私钥
    char* priv_key_hex = BN_bn2hex(kg.GetPrivateKey());
    std::cout << "Private Key: " << priv_key_hex << std::endl;
    OPENSSL_free(priv_key_hex);

    // 打印公钥
    EC_GROUP* group = kg.GetGroup();
    char* pub_key_hex = EC_POINT_point2hex(group, kg.GetPublicKey(), POINT_CONVERSION_UNCOMPRESSED, nullptr);
    std::cout << "Public Key: " << pub_key_hex << std::endl;
    OPENSSL_free(pub_key_hex);

    // 打印群的阶
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);
    char* order_hex = BN_bn2hex(order);
    std::cout << "Group Order: " << order_hex << std::endl;
    OPENSSL_free(order_hex);
    BN_free(order);

    // 打印生成元
    const EC_POINT* generator = EC_GROUP_get0_generator(group);
    char* generator_hex = EC_POINT_point2hex(group, generator, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    std::cout << "Generator: " << generator_hex << std::endl;
    OPENSSL_free(generator_hex);

    // 打印哈希密钥
    const auto& hash_keys = kg.GetHashKeys();  // 假设在KeyGenerator中实现了GetHashKeys方法返回hash_keys_引用
    std::cout << "Hash Keys:" << std::endl;
    for (const auto& key : hash_keys) {
        std::cout << "  - " << key << std::endl;
    }
}


void TestKeyGenerator() {
    KeyGenerator kg;

    // 初始化密钥生成器
    try {
        kg.Initialize();
        std::cout << "KeyGenerator initialized successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Initialization failed: " << e.what() << std::endl;
        return;
    }

    // 打印初始化后的配置信息
    std::cout << "Configuration after initialization:" << std::endl;
    PrintConfig(kg);

    // 测试默认路径保存配置
    try {
        kg.SaveConfig();
        std::cout << "Configuration saved successfully to default paths." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to save configuration to default paths: " << e.what() << std::endl;
        return;
    }

    // 测试默认路径加载配置
    KeyGenerator kg_loaded;
    try {
        kg_loaded.LoadConfig();
        std::cout << "Configuration loaded successfully from default paths." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to load configuration from default paths: " << e.what() << std::endl;
        return;
    }

    // 打印加载后的配置信息
    std::cout << "Configuration after loading:" << std::endl;
    PrintConfig(kg_loaded);

    // 验证加载的配置是否与原始配置一致
    assert(kg_loaded.GetCurveNid() == kg.GetCurveNid());
    assert(kg_loaded.GetHashType() == kg.GetHashType());
    assert(BN_cmp(kg_loaded.GetPrivateKey(), kg.GetPrivateKey()) == 0);

    // 使用 EC_GROUP 比较公钥
    EC_GROUP* group = kg_loaded.GetGroup();
    assert(EC_POINT_cmp(group, kg_loaded.GetPublicKey(), kg.GetPublicKey(), nullptr) == 0);
    EC_GROUP_free(group); // 释放 EC_GROUP

    std::cout << "All tests passed successfully with default paths!" << std::endl;
}

} // namespace ring_signature_lib

int main() {
    ring_signature_lib::TestKeyGenerator();
    return 0;
}
