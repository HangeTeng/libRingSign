#include "hash.h"
#include <iostream>
#include <openssl/bn.h>

using namespace ring_signature_lib;

void testHash(const std::string& data, const std::string& type) {
    try {
        // 创建带特定密钥和哈希类型的 Hash 实例
        Hash hash("test_key", type);

        // 计算数据的哈希值
        BIGNUM* hash_result = hash.hashToBn(data);

        // 输出哈希值
        char* hex_result = BN_bn2hex(hash_result);
        std::cout << "Hash result (" << data << "): " << hex_result << std::endl;

        // 清理内存
        OPENSSL_free(hex_result);
        BN_free(hash_result);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main() {
    std::string data = "Hello, world!";
    
    // 测试不同哈希算法
    std::cout << "Testing SHA256:" << std::endl;
    testHash(data, "SHA256");

    std::cout << "Testing SHA512:" << std::endl;
    testHash(data, "SHA512");

    std::cout << "Testing MD5:" << std::endl;
    testHash(data, "MD5");

    std::cout << "Testing SM3:" << std::endl;
    testHash(data, "SM3");

    return 0;
}
