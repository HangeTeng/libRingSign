#ifndef RING_SIGNATURE_LIB_CONFIG_H
#define RING_SIGNATURE_LIB_CONFIG_H

#include <string>
#include <openssl/obj_mac.h>
#include <nlohmann/json.hpp>

namespace ring_signature_lib {

const std::string DEFAULT_HASH_TYPE = "SHA256";
const int DEFAULT_CURVE_NID = NID_secp256k1;

const std::string DEFAULT_CONFIG_PATH = "config/system_config.json";
const std::string DEFAULT_KEY_PATH = "config/system_key.json";

const std::string DEFAULT_SIGN_KEY_PATH = "config/sign_key.json";

class ConfigManager {
public:
    static nlohmann::json LoadJson(const std::string& path);
    static void SaveJson(const std::string& path, const nlohmann::json& j);
};

} // namespace ring_signature_lib

#endif // RING_SIGNATURE_LIB_CONFIG_H
