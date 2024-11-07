#ifndef RING_SIGNATURE_LIB_HASH_H
#define RING_SIGNATURE_LIB_HASH_H

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <string>
#include <stdexcept>

namespace ring_signature_lib {

class Hash {
public:
    // 构造函数，接受哈希密钥和哈希算法名称
    Hash(const std::string& key, const std::string& type = "SHA256");

    // 计算哈希值，并返回 BIGNUM 格式
    BIGNUM* hashToBn(const std::string& data) const;

    // 返回哈希密钥
    std::string GetKey() const { return hash_key; }

    // 返回哈希类型
    std::string GetType() const { return hash_type; }

private:
    std::string hash_key;   // 哈希密钥
    std::string hash_type;  // 哈希算法名称
    const EVP_MD* evp_md;   // OpenSSL EVP_MD 指针，用于指定哈希算法
};

} // namespace ring_signature_lib

#endif // RING_SIGNATURE_LIB_HASH_H
