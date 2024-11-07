#ifndef RING_SIGNATURE_LIB_CONFIG_H
#define RING_SIGNATURE_LIB_CONFIG_H

#include <string>

namespace ring_signature_lib {


const std::string DEFAULT_HASH_TYPE = "SHA256";
const int DEFAULT_CURVE_NID = NID_secp256k1;

const std::string DEFAULT_CONFIG_PATH = "config/system_config.json";
const std::string DEFAULT_KEY_PATH = "config/system_key.json";

const std::string DEFAULT_SIGN_KEY_PATH = "config/sign_key.json";

} // namespace ring_signature_lib

#endif // RING_SIGNATURE_LIB_CONFIG_H
