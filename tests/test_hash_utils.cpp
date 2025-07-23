#include "libringsign/hash_utils.h"
#include <iostream>
#include <openssl/bn.h>

using namespace ring_signature_lib;

void testHash(const std::string& data, const std::string& type) {
    try {
        HashUtils hash("test_key", type);
        BIGNUM* hash_result = hash.hashToBn(data);
        char* hex_result = BN_bn2hex(hash_result);
        std::cout << "Hash result (" << data << ", " << type << "): " << hex_result << std::endl;
        OPENSSL_free(hex_result);
        BN_free(hash_result);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main() {
    std::string data = "Hello, world!";
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
