#include "libringsign/key_generator.h"
#include "libringsign/config_manager.h"
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <stdexcept>
#include <iostream>
#include <ctime>
#include <fstream>


using json = nlohmann::json;

namespace ring_signature_lib {

KeyGenerator::KeyGenerator() 
    : curve_nid_(DEFAULT_CURVE_NID),
      hash_type_(DEFAULT_HASH_TYPE),
      group_(nullptr),
      private_key_(nullptr),
      public_key_(nullptr),
      hash_keys_(5),
      hash_(),
      is_initialized_(false) {}

void KeyGenerator::Initialize(unsigned int seed) {
    if (is_initialized_) {
        throw std::runtime_error("Already initialized");
    }
    initialize(seed);
    is_initialized_ = true;
}

void KeyGenerator::initialize(unsigned int seed) {
    curve_nid_ = DEFAULT_CURVE_NID;
    hash_type_ = DEFAULT_HASH_TYPE;

    // 使用当前时间作为随机种子（如果 seed == 0）
    if (seed == 0) {
        seed = static_cast<unsigned int>(std::time(nullptr));
    }
    srand(seed);

    // 使用 curve_nid_ 创建群 group_
    group_ = EC_GROUP_new_by_curve_name(curve_nid_);
    if (!group_) {
        throw std::runtime_error("Failed to create EC group");
    }

    // 获取群的阶，确保私钥在阶范围内
    BIGNUM* group_order = BN_new();
    if (!group_order || !EC_GROUP_get_order(group_, group_order, nullptr)) {
        EC_GROUP_free(group_);
        BN_free(group_order);
        throw std::runtime_error("Failed to get group order");
    }

    // 生成私钥，使其在群的阶内
    private_key_ = BN_new();
    if (!private_key_ || !BN_rand_range(private_key_, group_order)) {
        EC_GROUP_free(group_);
        BN_free(group_order);
        throw std::runtime_error("Failed to generate private key within group order");
    }
    BN_free(group_order);

    // 使用 group_ 生成公钥
    public_key_ = EC_POINT_new(group_);
    if (!public_key_ || !EC_POINT_mul(group_, public_key_, private_key_, nullptr, nullptr, nullptr)) {
        EC_GROUP_free(group_);
        throw std::runtime_error("Failed to generate public key");
    }

    // 生成哈希密钥
    for (size_t i = 0; i < hash_keys_.size(); ++i) {
        std::string key = "hash_key_" + std::to_string(rand());
        hash_keys_[i] = key;
        hash_.emplace_back(key, hash_type_);
    }
}

void KeyGenerator::SaveConfig(const std::string& config_path, const std::string& system_key_path) {
    if (!is_initialized_) {
        throw std::runtime_error("System not initialized");
    }

    save_public_config(config_path);
    save_keys(system_key_path);
}

void KeyGenerator::LoadConfig(const std::string& config_path, const std::string& system_key_path) {
    load_public_config(config_path);
    load_keys(system_key_path);

    is_initialized_ = true;
}

void KeyGenerator::save_public_config(const std::string& config_path) {
    json j;
    j["curve_nid"] = curve_nid_;
    j["hash_type"] = hash_type_;

    // 将公钥转换为十六进制并保存
    char* pub_key_hex = EC_POINT_point2hex(group_, public_key_, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    j["system_public_key"] = pub_key_hex;
    OPENSSL_free(pub_key_hex);

    // 保存哈希密钥
    for (const auto& key : hash_keys_) {
        j["hash_keys"].push_back(key);
    }

    std::ofstream file(config_path);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
    } else {
        throw std::runtime_error("Failed to open config file for saving");
    }
}

void KeyGenerator::load_public_config(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open config file for loading");
    }

    json j;
    file >> j;
    file.close();

    curve_nid_ = j["curve_nid"];
    hash_type_ = j["hash_type"];

    // 如果未初始化 group_，使用 curve_nid_ 创建
    if (!group_) {
        group_ = EC_GROUP_new_by_curve_name(curve_nid_);
        if (!group_) {
            throw std::runtime_error("Failed to create EC group");
        }
    }

    // 加载公钥
    std::string pub_key_hex = j["system_public_key"];
    public_key_ = EC_POINT_new(group_);
    if (!EC_POINT_hex2point(group_, pub_key_hex.c_str(), public_key_, nullptr)) {
        EC_GROUP_free(group_);
        throw std::runtime_error("Failed to parse public key from hex");
    }

    // 加载哈希密钥
    hash_keys_ = j["hash_keys"].get<std::vector<std::string>>();
    hash_.clear();
    for (const auto& key : hash_keys_) {
        hash_.emplace_back(key, hash_type_);
    }
}

void KeyGenerator::save_keys(const std::string& system_key_path) {
    json j;

    // 保存公钥
    char* pub_key_hex = EC_POINT_point2hex(group_, public_key_, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    j["system_public_key"] = pub_key_hex;
    OPENSSL_free(pub_key_hex);

    // 保存私钥
    char* private_key_hex = BN_bn2hex(private_key_);
    j["system_private_key"] = private_key_hex;
    OPENSSL_free(private_key_hex);

    std::ofstream key_file(system_key_path);
    if (key_file.is_open()) {
        key_file << j.dump(4);
        key_file.close();
    } else {
        throw std::runtime_error("Failed to open key file for saving");
    }
}

void KeyGenerator::load_keys(const std::string& system_key_path) {
    std::ifstream key_file(system_key_path);
    if (!key_file.is_open()) {
        throw std::runtime_error("Failed to open key file for loading");
    }

    json j;
    key_file >> j;
    key_file.close();

    // 如果未初始化 group_，使用 curve_nid_ 创建
    if (!group_) {
        group_ = EC_GROUP_new_by_curve_name(curve_nid_);
        if (!group_) {
            throw std::runtime_error("Failed to create EC group");
        }
    }

    // 加载公钥
    std::string pub_key_hex = j["system_public_key"];
    public_key_ = EC_POINT_new(group_);
    if (!EC_POINT_hex2point(group_, pub_key_hex.c_str(), public_key_, nullptr)) {
        EC_GROUP_free(group_);
        throw std::runtime_error("Failed to parse public key from hex");
    }

    // 加载私钥
    std::string private_key_hex = j["system_private_key"];
    private_key_ = BN_new();
    if (!private_key_ || !BN_hex2bn(&private_key_, private_key_hex.c_str())) {
        throw std::runtime_error("Failed to load private key from hex");
    }
}

std::pair<EC_POINT*, BIGNUM*> KeyGenerator::GenerateSignKey(const std::string& signer_id, const EC_POINT* signer_public_key, unsigned int seed) {
    if (!is_initialized_) {
        throw std::runtime_error("System not initialized");
    }

    // 使用指定的种子初始化随机数生成器（若 seed 为 0 则使用当前时间）
    if (seed == 0) {
        seed = static_cast<unsigned int>(std::time(nullptr));
    }
    srand(seed);

    // Step 1: 计算 h_i = H_1(signer_id || X_i || P_pub)
    std::string data = signer_id + 
                       EC_POINT_point2hex(group_, signer_public_key, POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                       EC_POINT_point2hex(group_, public_key_, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    BIGNUM* id_hash = hash_[1].hashToBn(data);  // 使用 H_1 哈希计算

    // Step 2: 计算 y_i = H_2(signer_id || 系统参数)
    std::string system_state_param = "system_state_" + std::to_string(seed);  // 系统状态参数 ξ，包含 seed
    data = signer_id + system_state_param;
    BIGNUM* partial_system_key = hash_[2].hashToBn(data);  // 使用 H_2 哈希计算

    // Step 3: 计算部分公钥 Y_i = y_i * G，直接使用 group_ 的生成元
    EC_POINT* partial_system_public_key = EC_POINT_new(group_);
    if (!partial_system_public_key || !EC_POINT_mul(group_, partial_system_public_key, partial_system_key, nullptr, nullptr, nullptr)) {
        BN_free(id_hash);
        BN_free(partial_system_key);
        EC_POINT_free(partial_system_public_key);
        throw std::runtime_error("Failed to calculate partial public key");
    }

    // Step 4: 计算部分私钥 z_i = y_i + h_i * s
    BIGNUM* partial_private_key = BN_new();
    BIGNUM* temp = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    if (!partial_private_key || !temp || !ctx) {
        BN_free(id_hash);
        BN_free(partial_system_key);
        EC_POINT_free(partial_system_public_key);
        BN_free(temp);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUMs for partial private key calculation");
    }

    // temp = h_i * s
    if (!BN_mul(temp, id_hash, private_key_, ctx)) {
        throw std::runtime_error("Failed to calculate h_i * s");
    }
    // z_i = y_i + temp
    if (!BN_add(partial_private_key, partial_system_key, temp)) {
        throw std::runtime_error("Failed to calculate partial private key");
    }

    // 清理临时变量
    BN_free(id_hash);
    BN_free(partial_system_key);
    BN_free(temp);
    BN_CTX_free(ctx);

    // 返回部分公钥 Y_i 和部分私钥 z_i
    return {partial_system_public_key, partial_private_key};
}

} // namespace ring_signature_lib
