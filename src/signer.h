#ifndef RING_SIGNATURE_LIB_SIGNER_H
#define RING_SIGNATURE_LIB_SIGNER_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <string>
#include <nlohmann/json.hpp>
#include <fstream>
#include "hash.h"
#include "config.h"

namespace ring_signature_lib {

struct Signature {
    std::vector<EC_POINT*> A;  // 多个签名点
    BIGNUM* phi;               // 签名的一部分
    BIGNUM* psi;               // 签名的另一部分
    EC_POINT* T;               // 签名的点 T

    Signature(std::vector<EC_POINT*> A, BIGNUM* phi, BIGNUM* psi, EC_POINT* T)
        : A(std::move(A)), phi(phi), psi(psi), T(T) {}
};

class Signer {

public:
    Signer();

    // 初始化函数，传入ID和配置文件路径，加载配置并完成初始化
    void Initialize(const std::string& id, const std::string& config_path);

    // 生成用户密钥对并向 KGC 请求部分密钥
    std::pair<std::string, EC_POINT*> GeneratePartialKey(unsigned int seed = 0);

    // 接收并生成完整的用户密钥
    void GenerateFullKey(const EC_POINT* partial_system_public_key, const BIGNUM* partial_private_key);

    // 验证密钥是否正确
    bool VerifyKey() const;

    // 保存和加载密钥配置信息，带有默认路径
    void SaveConfig(const std::string& sign_key_path = DEFAULT_SIGN_KEY_PATH);
    void LoadConfig(const std::string& config_path = DEFAULT_CONFIG_PATH, const std::string& sign_key_path = DEFAULT_SIGN_KEY_PATH);


    // 获取私钥和部分私钥的接口
    const BIGNUM* GetPrivateKey() const { return private_key_; }
    const BIGNUM* GetPartialPrivateKey() const { return partial_private_key_; }
    // 获取完整的用户公钥
    std::pair<EC_POINT*, EC_POINT*> GetPublicKey() const { return {full_public_key_[0], full_public_key_[1]}; }
    EC_GROUP* GetGroup() const { return group_; }

    // 获取所有参数的字符串表示，用于测试和比较
    std::string GetParametersAsString() const;

    // 生成环签名的公开接口：用于输入验证
    Signature Sign(
        const std::string& msg, const std::string& event,
        std::vector<std::pair<std::string, std::pair<EC_POINT*, EC_POINT*>>> other_signer_pkc);




private:
    std::string id_;                        // 用户ID
    BIGNUM* private_key_;                   // 用户的私钥 x_i
    EC_POINT* full_public_key_[2];          // 用户的完整公钥，包含 X_i 和 Y_i
    BIGNUM* partial_private_key_;           // 用户的部分私钥 z_i
    BIGNUM* id_hash_;                       // ID绑定的哈希值 H_1(ID_i || X_i || P_pub)
    EC_POINT* system_public_key_;           // 系统公钥 P_pub
    EC_GROUP* group_;                       // 椭圆曲线群
    std::vector<Hash> hash_;                // 哈希函数列表
    int curve_nid_;                         // 椭圆曲线的 NID
    std::string hash_type_;                 // 哈希类型

    bool is_initialized_;                   // 标识是否已初始化
    bool is_partial_key_generated_;         // 标识是否生成了部分密钥
    bool is_full_key_generated_;            // 标识是否生成了完整密钥

    void initialize_id(const std::string& id);
    void load_config(const std::string& path);
    void generate_partial_key(unsigned int seed);
    void generate_full_key(const EC_POINT* partial_system_public_key, const BIGNUM* partial_private_key);
    bool verify_key(const EC_POINT* partial_system_public_key, const BIGNUM* partial_private_key) const;
    void save_key(const std::string& sign_key_path);
    void load_key(const std::string& sign_key_path);

    // 私有的签名生成函数：实现具体签名生成逻辑
    std::tuple<std::vector<EC_POINT*>, BIGNUM*, BIGNUM*, EC_POINT*> sign(
        const std::string& msg, const std::string& event,
        const std::vector<std::pair<std::string, std::pair<EC_POINT*, EC_POINT*>>>& L, int signer_index);

    // 验证函数声明
    bool verify(
        const std::vector<EC_POINT*>& A,
        BIGNUM* phi,
        BIGNUM* psi,
        EC_POINT* T,
        const std::string& msg,
        const std::string& event,
        const std::vector<std::pair<std::string, std::pair<EC_POINT*, EC_POINT*>>>& L);
};

} // namespace ring_signature_lib

#endif // RING_SIGNATURE_LIB_SIGNER_H
