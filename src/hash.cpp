#include "hash.h"
#include <openssl/evp.h>
#include <stdexcept>

namespace ring_signature_lib {

Hash::Hash(const std::string& key, const std::string& type) : hash_key(key), hash_type(type) {
    // 根据字符串选择 EVP_MD
    if (type == "SHA256") {
        evp_md = EVP_sha256();
    } else if (type == "SHA512") {
        evp_md = EVP_sha512();
    } else if (type == "MD5") {
        evp_md = EVP_md5();
    } else if (type == "SM3") {
        evp_md = EVP_sm3();
    } else {
        throw std::invalid_argument("Unsupported hash type");
    }
}

BIGNUM* Hash::hashToBn(const std::string& data) const {
    // 使用选定的哈希算法计算 HMAC
    unsigned char hash[EVP_MAX_MD_SIZE];
    size_t hash_len;

    // 使用 EVP_MAC 生成 HMAC
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        throw std::runtime_error("Failed to fetch HMAC");
    }

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) {
        throw std::runtime_error("Failed to create HMAC context");
    }

    // 设置 MAC 的参数
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(EVP_MD_get0_name(evp_md)), 0),
        OSSL_PARAM_END
    };
    EVP_MAC_init(ctx, reinterpret_cast<const unsigned char*>(hash_key.c_str()), hash_key.length(), params);
    EVP_MAC_update(ctx, reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
    EVP_MAC_final(ctx, hash, &hash_len, sizeof(hash));
    EVP_MAC_CTX_free(ctx);

    // 将哈希值转换为 BIGNUM
    BIGNUM* result = BN_bin2bn(hash, hash_len, nullptr);
    if (!result) {
        throw std::runtime_error("Failed to convert hash to BIGNUM");
    }

    return result;
}

} // namespace ring_signature_lib
