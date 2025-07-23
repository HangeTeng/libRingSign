#include "libringsign/hash_utils.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/macros.h>
#include <openssl/params.h>
#include <openssl/hmac.h>
#include <stdexcept>

namespace ring_signature_lib {

HashUtils::HashUtils(const std::string& key, const std::string& type) : hash_key_(key), hash_type_(type) {
    if (type == "SHA256") {
        evp_md_ = EVP_sha256();
    } else if (type == "SHA512") {
        evp_md_ = EVP_sha512();
    } else if (type == "MD5") {
        evp_md_ = EVP_md5();
    } else if (type == "SM3") {
        evp_md_ = EVP_sm3();
    } else {
        throw std::invalid_argument("Unsupported hash type");
    }
}

BIGNUM* HashUtils::hashToBn(const std::string& data) const {
    unsigned char hash[EVP_MAX_MD_SIZE];
    size_t hash_len;

    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        throw std::runtime_error("Failed to fetch HMAC");
    }

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) {
        throw std::runtime_error("Failed to create HMAC context");
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(EVP_MD_get0_name(evp_md_)), 0),
        OSSL_PARAM_END
    };
    EVP_MAC_init(ctx, reinterpret_cast<const unsigned char*>(hash_key_.c_str()), hash_key_.length(), params);
    EVP_MAC_update(ctx, reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
    EVP_MAC_final(ctx, hash, &hash_len, sizeof(hash));
    EVP_MAC_CTX_free(ctx);

    BIGNUM* result = BN_bin2bn(hash, hash_len, nullptr);
    if (!result) {
        throw std::runtime_error("Failed to convert hash to BIGNUM");
    }
    return result;
}

} // namespace ring_signature_lib
