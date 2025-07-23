#ifndef RING_SIGNATURE_LIB_HASH_UTILS_H
#define RING_SIGNATURE_LIB_HASH_UTILS_H

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <string>
#include <stdexcept>

namespace ring_signature_lib {

class HashUtils {
public:
    // 构造函数，接受哈希密钥和哈希算法名称
    HashUtils(const std::string& key, const std::string& type = "SHA256");

    // 计算哈希值，并返回 BIGNUM 格式
    BIGNUM* hashToBn(const std::string& data) const;

    // 返回哈希密钥
    std::string GetKey() const { return hash_key_; }

    // 返回哈希类型
    std::string GetType() const { return hash_type_; }

private:
    std::string hash_key_;
    std::string hash_type_;
    const EVP_MD* evp_md_;
};

} // namespace ring_signature_lib

#endif // RING_SIGNATURE_LIB_HASH_UTILS_H
