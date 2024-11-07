#ifndef RING_SIGNATURE_LIB_KEY_GENERATOR_H
#define RING_SIGNATURE_LIB_KEY_GENERATOR_H

#include <string>
#include <vector>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <nlohmann/json.hpp>
#include "hash.h"
#include "config.h"

namespace ring_signature_lib {

class KeyGenerator {
public:
    KeyGenerator();

    void Initialize(unsigned int seed = 0);

    void SaveConfig(const std::string& config_path = DEFAULT_CONFIG_PATH,
                    const std::string& system_key_path = DEFAULT_KEY_PATH);

    void LoadConfig(const std::string& config_path = DEFAULT_CONFIG_PATH,
                    const std::string& system_key_path = DEFAULT_KEY_PATH);

    int GetCurveNid() const { return curve_nid_; }
    std::string GetHashType() const { return hash_type_; }
    const BIGNUM* GetPrivateKey() const { return private_key_; }
    const EC_POINT* GetPublicKey() const { return public_key_; }
    EC_GROUP* GetGroup() const { return group_; }
    const std::vector<std::string>& GetHashKeys() const {
    return hash_keys_;
}

    std::pair<EC_POINT*, BIGNUM*> GenerateSignKey(const std::string& signer_id, const EC_POINT* signer_public_key, unsigned int seed = 0);

private:
    int curve_nid_;
    std::string hash_type_;
    EC_GROUP* group_;
    BIGNUM* private_key_;
    EC_POINT* public_key_;
    std::vector<std::string> hash_keys_;
    std::vector<Hash> hash_;
    bool is_initialized_;

    void initialize(unsigned int seed);
    void save_public_config(const std::string& config_path);
    void load_public_config(const std::string& config_path);
    void save_keys(const std::string& system_key_path);
    void load_keys(const std::string& system_key_path);
    std::pair<EC_POINT*, BIGNUM*> generate_sign_key(const std::string& signer_id, const EC_POINT* signer_public_key, unsigned int seed);
};

} // namespace ring_signature_lib

#endif // RING_SIGNATURE_LIB_KEY_GENERATOR_H
