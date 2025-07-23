#include "libringsign/key_generator.h"
#include "libringsign/config_manager.h"
#include <iostream>
#include <openssl/bn.h>
#include <cassert>

using namespace ring_signature_lib;

void PrintConfig(const KeyGenerator& kg) {
    std::cout << "Curve NID: " << kg.GetCurveNid() << std::endl;
    std::cout << "Hash Type: " << kg.GetHashType() << std::endl;
    char* priv_hex = BN_bn2hex(kg.GetPrivateKey());
    std::cout << "Private Key: " << priv_hex << std::endl;
    OPENSSL_free(priv_hex);
    char* pub_hex = EC_POINT_point2hex(kg.GetGroup(), kg.GetPublicKey(), POINT_CONVERSION_UNCOMPRESSED, nullptr);
    std::cout << "Public Key: " << pub_hex << std::endl;
    OPENSSL_free(pub_hex);
}

void TestKeyGenerator() {
    KeyGenerator kg;
    try {
        kg.Initialize();
        std::cout << "KeyGenerator initialized successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Initialization failed: " << e.what() << std::endl;
        return;
    }
    std::cout << "Configuration after initialization:" << std::endl;
    PrintConfig(kg);
    try {
        kg.SaveConfig();
        std::cout << "Configuration saved successfully to default paths." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to save configuration to default paths: " << e.what() << std::endl;
        return;
    }
    KeyGenerator kg_loaded;
    try {
        kg_loaded.LoadConfig();
        std::cout << "Configuration loaded successfully from default paths." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Failed to load configuration from default paths: " << e.what() << std::endl;
        return;
    }
    std::cout << "Configuration after loading:" << std::endl;
    PrintConfig(kg_loaded);
    assert(kg_loaded.GetCurveNid() == kg.GetCurveNid());
    assert(kg_loaded.GetHashType() == kg.GetHashType());
    assert(BN_cmp(kg_loaded.GetPrivateKey(), kg.GetPrivateKey()) == 0);
    EC_GROUP* group = kg_loaded.GetGroup();
    assert(EC_POINT_cmp(group, kg_loaded.GetPublicKey(), kg.GetPublicKey(), nullptr) == 0);
    EC_GROUP_free(group);
    std::cout << "All tests passed successfully with default paths!" << std::endl;
}

int main() {
    TestKeyGenerator();
    return 0;
}
