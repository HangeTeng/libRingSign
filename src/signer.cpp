#include "libringsign/signer.h"
#include <openssl/rand.h>
#include <stdexcept>
#include <iostream>

namespace ring_signature_lib {

using json = nlohmann::json;

Signer::Signer()
    : private_key_(nullptr),
      partial_private_key_(nullptr),
      id_hash_(nullptr),
      system_public_key_(nullptr),
      group_(nullptr),
      is_initialized_(false),
      is_partial_key_generated_(false),
      is_full_key_generated_(false),
      curve_nid_(0) {
    full_public_key_[0] = nullptr;
    full_public_key_[1] = nullptr;
}

void Signer::Initialize(const std::string& id, const std::string& config_path) {
    initialize_id(id);
    load_config(config_path);
    is_initialized_ = true;
}

void Signer::initialize_id(const std::string& id) {
    id_ = id;  // 设置用户ID
}

void Signer::load_config(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open config file");
    }

    json j;
    file >> j;
    file.close();

    curve_nid_ = j["curve_nid"];
    hash_type_ = j["hash_type"];

    // 初始化群 group_
    group_ = EC_GROUP_new_by_curve_name(curve_nid_);
    if (!group_) {
        throw std::runtime_error("Failed to create EC group");
    }

    system_public_key_ = EC_POINT_new(group_);
    EC_POINT_hex2point(group_, j["system_public_key"].get<std::string>().c_str(), system_public_key_, nullptr);

    for (const auto& key : j["hash_keys"]) {
        hash_.emplace_back(key, hash_type_);
    }
}

std::pair<std::string, EC_POINT*> Signer::GeneratePartialKey(unsigned int seed) {
    if (!is_initialized_) {
        throw std::runtime_error("System configuration not loaded.");
    }

    generate_partial_key(seed);
    is_partial_key_generated_ = true;
    return {id_, full_public_key_[0]};
}

void Signer::generate_partial_key(unsigned int seed) {
    if (seed == 0) {
        seed = static_cast<unsigned int>(std::time(nullptr));
    }
    srand(seed);

    private_key_ = BN_new();
    BIGNUM* group_order = BN_new();
    EC_GROUP_get_order(group_, group_order, nullptr);
    if (!private_key_ || !BN_rand_range(private_key_, group_order)) {
        BN_free(group_order);
        throw std::runtime_error("Failed to generate private key");
    }

    full_public_key_[0] = EC_POINT_new(group_);

    // 直接将生成元作为参数传递，而不是存储在非 const 变量中
    if (!full_public_key_[0] || !EC_POINT_mul(group_, full_public_key_[0], private_key_, nullptr, nullptr, nullptr)) {
        BN_free(group_order);
        throw std::runtime_error("Failed to generate partial public key");
    }

    std::string data = id_ + EC_POINT_point2hex(group_, full_public_key_[0], POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                       EC_POINT_point2hex(group_, system_public_key_, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    id_hash_ = hash_[1].hashToBn(data);
    BN_free(group_order);
}

void Signer::GenerateFullKey(const EC_POINT* partial_system_public_key, const BIGNUM* partial_private_key) {
    if (!is_partial_key_generated_) {
        throw std::runtime_error("Partial key not generated.");
    }

    generate_full_key(partial_system_public_key, partial_private_key);
    is_full_key_generated_ = true;
}

void Signer::generate_full_key(const EC_POINT* partial_system_public_key, const BIGNUM* partial_private_key) {
    full_public_key_[1] = EC_POINT_dup(partial_system_public_key, group_);
    partial_private_key_ = BN_dup(partial_private_key);
}

bool Signer::VerifyKey() const {
    if (!is_full_key_generated_) return false;

    return verify_key(full_public_key_[1], partial_private_key_);
}

bool Signer::verify_key(const EC_POINT* partial_system_public_key, const BIGNUM* partial_private_key) const {
    EC_POINT* lhs = EC_POINT_new(group_);
    EC_POINT* rhs = EC_POINT_new(group_);

    // 将生成元直接传递给 EC_POINT_mul
    EC_POINT_mul(group_, lhs, nullptr, system_public_key_, id_hash_, nullptr);
    EC_POINT_add(group_, lhs, partial_system_public_key, lhs, nullptr);
    EC_POINT_mul(group_, rhs, partial_private_key, nullptr, nullptr, nullptr);

    bool is_valid = (EC_POINT_cmp(group_, lhs, rhs, nullptr) == 0);

    EC_POINT_free(lhs);
    EC_POINT_free(rhs);

    return is_valid;
}

void Signer::SaveConfig(const std::string& sign_key_path) {
    if (!is_full_key_generated_) {
        throw std::runtime_error("Full key is not generated.");
    }
    save_key(sign_key_path);
}

void Signer::LoadConfig(const std::string& config_path, const std::string& sign_key_path) {
    load_config(config_path);
    load_key(sign_key_path);

    // 设置所有标志为已加载完成状态
    is_initialized_ = true;
    is_partial_key_generated_ = true;
    is_full_key_generated_ = true;
}

void Signer::save_key(const std::string& sign_key_path) {
    json j;

    j["id"] = id_;  // 保存用户ID

    // 保存私钥
    char* private_key_hex = BN_bn2hex(private_key_);
    j["private_key"] = private_key_hex;
    OPENSSL_free(private_key_hex);

    // 保存部分私钥
    char* partial_private_key_hex = BN_bn2hex(partial_private_key_);
    j["partial_private_key"] = partial_private_key_hex;
    OPENSSL_free(partial_private_key_hex);

    // 保存完整公钥（X_i 和 Y_i）
    for (int i = 0; i < 2; ++i) {
        if (full_public_key_[i] != nullptr) {
            char* public_key_hex = EC_POINT_point2hex(group_, full_public_key_[i], POINT_CONVERSION_UNCOMPRESSED, nullptr);
            j["full_public_key_" + std::to_string(i)] = public_key_hex;
            OPENSSL_free(public_key_hex);
        }
    }

    // 将密钥信息写入文件
    std::ofstream file(sign_key_path);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
    } else {
        throw std::runtime_error("Failed to open file for saving keys.");
    }
}

void Signer::load_key(const std::string& sign_key_path) {
    std::ifstream file(sign_key_path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file for loading keys.");
    }

    json j;
    file >> j;
    file.close();

    id_ = j["id"];  // 加载用户ID

    // 加载私钥
    std::string private_key_hex = j["private_key"];
    private_key_ = BN_new();
    BN_hex2bn(&private_key_, private_key_hex.c_str());

    // 加载部分私钥
    std::string partial_private_key_hex = j["partial_private_key"];
    partial_private_key_ = BN_new();
    BN_hex2bn(&partial_private_key_, partial_private_key_hex.c_str());

    // 加载完整公钥（X_i 和 Y_i）
    for (int i = 0; i < 2; ++i) {
        std::string public_key_key = "full_public_key_" + std::to_string(i);
        if (j.contains(public_key_key)) {
            std::string public_key_hex = j[public_key_key];
            full_public_key_[i] = EC_POINT_new(group_);
            EC_POINT_hex2point(group_, public_key_hex.c_str(), full_public_key_[i], nullptr);
        }
    }

    // 检查 hash_、group_ 和 system_public_key_ 是否已初始化
    if (hash_.empty() || !group_ || !system_public_key_) {
        throw std::runtime_error("Required components for ID hash calculation are not initialized.");
    }
    
    // 检查 full_public_key_[0] 是否有效
    if (!full_public_key_[0]) {
        throw std::runtime_error("Full public key X_i is not initialized.");
    }

    // 计算 ID 的哈希值
    std::string data = id_ + 
                       EC_POINT_point2hex(group_, full_public_key_[0], POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                       EC_POINT_point2hex(group_, system_public_key_, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    id_hash_ = hash_[1].hashToBn(data);
}

std::string Signer::GetParametersAsString() const {
    std::ostringstream oss;

    oss << "ID: " << id_ << "\n";
    oss << "Private Key: " << BN_bn2hex(private_key_) << "\n";
    oss << "Partial Private Key (z_i): " << BN_bn2hex(partial_private_key_) << "\n";
    oss << "ID Hash (H_1): " << BN_bn2hex(id_hash_) << "\n";

    // 输出公钥的 X_i 和 Y_i 部分
    oss << "Public Key X_i: " << EC_POINT_point2hex(group_, full_public_key_[0], POINT_CONVERSION_UNCOMPRESSED, nullptr) << "\n";
    oss << "Public Key Y_i: " << EC_POINT_point2hex(group_, full_public_key_[1], POINT_CONVERSION_UNCOMPRESSED, nullptr) << "\n";
     

    // 输出系统公钥
    oss << "System Public Key (P_pub): " << EC_POINT_point2hex(group_, system_public_key_, POINT_CONVERSION_UNCOMPRESSED, nullptr) << "\n";

    // 输出椭圆曲线和哈希类型
    oss << "Curve NID: " << curve_nid_ << "\n";
    oss << "Hash Type: " << hash_type_ << "\n";

    // 输出哈希函数列表的 key 和 type
    oss << "Hash Functions:\n";
    for (const auto& h : hash_) {
        oss << " - Key: " << h.GetKey() << ", Type: " << h.GetType() << "\n";
    }

    // 输出标志变量
    oss << "Is Initialized: " << (is_initialized_ ? "true" : "false") << "\n";
    oss << "Is Partial Key Generated: " << (is_partial_key_generated_ ? "true" : "false") << "\n";
    oss << "Is Full Key Generated: " << (is_full_key_generated_ ? "true" : "false") << "\n";

    return oss.str();
}

Signature Signer::Sign(
    const std::string& msg, const std::string& event,
    std::vector<std::pair<std::string, std::pair<EC_POINT*, EC_POINT*>>> other_signer_pkc) {

    // 将 signer 自己的信息（ID 和公钥）添加到 other_signer_pkc 中
    other_signer_pkc.emplace_back(id_, std::make_pair(full_public_key_[0], full_public_key_[1]));

    // 对包含 signer 自身信息的 other_signer_pkc 按照 ID 字符串字典序排序
    std::sort(other_signer_pkc.begin(), other_signer_pkc.end(), 
        [](const auto& lhs, const auto& rhs) {
            return lhs.first < rhs.first;
    });

    // 查找 signer 在排序后的列表中的位置（signer_index），并检查重复 ID
    int signer_index = -1;
    for (size_t i = 0; i < other_signer_pkc.size(); ++i) {
        if (i > 0 && other_signer_pkc[i].first == other_signer_pkc[i - 1].first) {
            throw std::invalid_argument("Duplicate ID found in other_signer_pkc.");
        }
        if (other_signer_pkc[i].first == id_) {
            signer_index = i;
        }
    }

    // 如果 signer_index 未找到，抛出异常（一般不会发生）
    if (signer_index == -1) {
        throw std::runtime_error("Signer ID not found in sorted list.");
    }

    // 调用私有的签名生成函数
    auto [A, phi, psi, T] = sign(msg, event, other_signer_pkc, signer_index);

    // 返回 Signature 结构体
    return Signature(A, phi, psi, T);
}

void print_bignum(const std::string& label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    std::cout << label << ": " << bn_str << std::endl;
    OPENSSL_free(bn_str);
}

// 辅助函数：打印 EC_POINT 内容
void print_ec_point(const std::string& label, const EC_GROUP* group, const EC_POINT* point) {
    char* point_str = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    std::cout << label << ": " << point_str << std::endl;
    OPENSSL_free(point_str);
}

std::tuple<std::vector<EC_POINT*>, BIGNUM*, BIGNUM*, EC_POINT*> Signer::sign(
    const std::string& msg, const std::string& event,
    const std::vector<std::pair<std::string, std::pair<EC_POINT*, EC_POINT*>>>& L,
    int signer_index) {

    BN_CTX* ctx = BN_CTX_new();
    const EC_POINT* P = EC_GROUP_get0_generator(group_);
    BIGNUM* group_order = BN_new();
    EC_GROUP_get_order(group_, group_order, ctx);

    // 复用的临时变量
    BIGNUM* temp_bn = BN_new();  // 用于各类中间 BIGNUM 计算，包括替代 random_bn
    EC_POINT* temp_point = EC_POINT_new(group_);

    // 步骤 1：选择随机值并生成 A_i 和 a_i
    std::vector<EC_POINT*> A(L.size(), nullptr);
    std::vector<BIGNUM*> a(L.size(), nullptr);

    for (int i = 0; i < L.size(); ++i) {
        if (i == signer_index) continue;  // 跳过 signer_index
        A[i] = EC_POINT_new(group_);
        // 生成随机数并计算 A_i
        BN_rand_range(temp_bn, group_order);
        EC_POINT_mul(group_, A[i], temp_bn, P, nullptr, ctx);
        // 拼接消息、事件和其他签名者信息计算 a_i
        // 计算 a_i = H_3(msg || event || L_i || A_i)
        std::string input = msg + event + L[i].first +
                            EC_POINT_point2hex(group_, L[i].second.first, POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                            EC_POINT_point2hex(group_, L[i].second.second, POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                            EC_POINT_point2hex(group_, A[i], POINT_CONVERSION_UNCOMPRESSED, nullptr);
        a[i] = hash_[3].hashToBn(input);
    }

    // 步骤 2：计算 h_i
    std::vector<BIGNUM*> h(L.size());
    for (int i = 0; i < L.size(); ++i) {
        if (i == signer_index) {
            // 对于 signer 自己，直接使用 id_hash_
            h[i] = BN_dup(id_hash_);
        } else {
            std::string h_input = L[i].first + EC_POINT_point2hex(group_, L[i].second.first, POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                                  EC_POINT_point2hex(group_, system_public_key_, POINT_CONVERSION_UNCOMPRESSED, nullptr);
            h[i] = hash_[1].hashToBn(h_input);
        }
    }

    // 步骤 3：计算 E 和 T
    EC_POINT* E = EC_POINT_new(group_);
    EC_POINT_mul(group_, E, nullptr, P, hash_[0].hashToBn(event), nullptr);
    EC_POINT* T = EC_POINT_new(group_);
    EC_POINT_mul(group_, T, nullptr, E, private_key_, nullptr); // T = x_signer * E

    // 步骤 4：选择随机值 μ 和 ν 并计算 M 和 N
    BIGNUM* mu = BN_new();
    BIGNUM* nu = BN_new();
    BN_rand_range(mu, group_order);
    BN_rand_range(nu, group_order);

    // 计算 M = (μ + ν)P + ∑_{i=1, i ≠ ω}^{n} a_i (X_i + Y_i + h_i P_{pub})
    EC_POINT* M = EC_POINT_new(group_);
    BN_mod_add(temp_bn, mu, nu, group_order, ctx);  // 复用 temp_bn 计算 μ + ν
    EC_POINT_mul(group_, M, nullptr, P, temp_bn, ctx);

    // 累加 M = (μ + ν)P + ∑_{i=1, i ≠ ω}^{n} a_i * (X_i + Y_i + h_i * P_pub)
    for (int i = 0; i < L.size(); ++i) {
        if (i == signer_index) continue;  // 跳过 signer 自己的索引

        EC_POINT_mul(group_, temp_point, nullptr, system_public_key_, h[i], ctx); // temp_point = h_i * P_pub
        EC_POINT_add(group_, temp_point, temp_point, L[i].second.first, ctx); // temp_point = h_i * P_pub + X_i
        EC_POINT_add(group_, temp_point, temp_point, L[i].second.second, ctx); // temp_point = X_i + Y_i + h_i * P_pub
        EC_POINT_mul(group_, temp_point, nullptr, temp_point, a[i], ctx);
        EC_POINT_add(group_, M, M, temp_point, ctx);
    }

    // 计算 N = ν E + ∑_{i=1, i ≠ signer_index}^{n} a_i T
    EC_POINT* N = EC_POINT_new(group_);
    EC_POINT_mul(group_, N, nullptr, E, nu, ctx);
    for (int i = 0; i < L.size(); ++i) {
        if (i == signer_index) continue;
        EC_POINT_mul(group_, temp_point, nullptr, T, a[i], ctx); // a_i T
        EC_POINT_add(group_, N, N, temp_point, ctx);
    }

    // 步骤 5：计算 θ
    std::string theta_input = msg + event + 
                              EC_POINT_point2hex(group_, T, POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                              EC_POINT_point2hex(group_, M, POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                              EC_POINT_point2hex(group_, N, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    for (const auto& entry : L) {
        theta_input += entry.first + 
                       EC_POINT_point2hex(group_, entry.second.first, POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                       EC_POINT_point2hex(group_, entry.second.second, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    }
    BIGNUM* theta = hash_[4].hashToBn(theta_input);

    // 步骤 6：计算 D 和 A_signer
    EC_POINT* D = EC_POINT_new(group_);
    EC_POINT_add(group_, D, M, N, ctx);               // D = M + N
    EC_POINT_mul(group_, temp_point, nullptr, P, theta, ctx);  // θP
    EC_POINT_add(group_, D, D, temp_point, ctx);               // D = M + N + θP

    // 计算 A[signer_index] = D - ∑_{i ≠ signer_index} A_i
    A[signer_index] = EC_POINT_dup(D, group_);
    for (int i = 0; i < L.size(); ++i) {
        if (i == signer_index) continue;

        EC_POINT_copy(temp_point, A[i]);
        EC_POINT_invert(group_, temp_point, ctx);  // 取反 A[i]
        EC_POINT_add(group_, A[signer_index], A[signer_index], temp_point, ctx);  // A[signer_index] = D - ∑ A_i
    }


    // 步骤 7：计算 a[signer_index] 和生成 φ, ψ
    std::string a_signer_input = msg + event + id_ +
                                  EC_POINT_point2hex(group_, full_public_key_[0], POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                                  EC_POINT_point2hex(group_, full_public_key_[1], POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                                  EC_POINT_point2hex(group_, A[signer_index], POINT_CONVERSION_UNCOMPRESSED, nullptr);
    a[signer_index] = hash_[3].hashToBn(a_signer_input);

    BIGNUM* phi = BN_new();
    BIGNUM* psi = BN_new();

    // 计算 φ = μ + θ - a[signer_index] * z_signer
    BN_mod_add(phi, mu, theta, group_order, ctx);               // 先计算 μ + θ，直接存入 φ
    BN_mod_mul(temp_bn, a[signer_index], partial_private_key_, group_order, ctx);  // 计算 a[signer_index] * z_signer 并存入 temp_bn
    BN_mod_sub(phi, phi, temp_bn, group_order, ctx);            // φ = μ + θ - a[signer_index] * z_signer

    // 计算 ψ = ν - a[signer_index] * x_signer
    BN_mod_mul(temp_bn, a[signer_index], private_key_, group_order, ctx);  // a[signer_index] * x_signer
    BN_mod_sub(psi, nu, temp_bn, group_order, ctx);      

    // 清理资源
    BN_free(group_order);
    BN_free(temp_bn);
    EC_POINT_free(temp_point);
    BN_CTX_free(ctx);

    // 验证签名
    bool is_valid = verify(A, phi, psi, T, msg, event, L);
    if (!is_valid) {
        // 可以选择抛出异常，或记录日志，或返回错误标志
        throw std::runtime_error("Signature verification failed after signing.");
    }
   
    return {A, phi, psi, T};
}

bool Signer::verify(
    const std::vector<EC_POINT*>& A,
    BIGNUM* phi,
    BIGNUM* psi,
    EC_POINT* T,
    const std::string& msg,
    const std::string& event,
    const std::vector<std::pair<std::string, std::pair<EC_POINT*, EC_POINT*>>>& L) {

        BN_CTX* ctx = BN_CTX_new();
        const EC_POINT* P = EC_GROUP_get0_generator(group_);
        BIGNUM *group_order = BN_new();
        EC_GROUP_get_order(group_, group_order, NULL);
        EC_POINT* lhs = EC_POINT_new(group_);  // 左侧求和项
        EC_POINT* rhs = EC_POINT_new(group_);  // 右侧求和项
        EC_POINT* temp_point = EC_POINT_new(group_);  // 临时计算点
        BIGNUM* temp_bn = BN_new();  // 用于存储中间 BIGNUM 值
 
        // 计算 E = H_0(event) * P
        EC_POINT* E = EC_POINT_new(group_);
        EC_POINT_mul(group_, E, nullptr, P, hash_[0].hashToBn(event), ctx);  // E = H_0(event) * P

        // 计算左侧: ∑_{i=1}^{n} A_i
        EC_POINT_set_to_infinity(group_, lhs);
        for (const auto& Ai : A) {
            EC_POINT_add(group_, lhs, lhs, Ai, ctx);
        }

        // 计算右侧
        EC_POINT_set_to_infinity(group_, rhs);  // 初始 rhs 为无穷点

        // 逐项计算右侧公式中的每一项
        for (size_t i = 0; i < L.size(); ++i) {
            // 计算 a_i = H_3(msg || event || L_i || A_i)
            std::string a_input = msg + event + L[i].first +
                                EC_POINT_point2hex(group_, L[i].second.first, POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                                EC_POINT_point2hex(group_, L[i].second.second, POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                                EC_POINT_point2hex(group_, A[i], POINT_CONVERSION_UNCOMPRESSED, nullptr);
            BIGNUM* a_i = hash_[3].hashToBn(a_input);

            // 计算 h_i = H_1(ID_i || X_i || P_pub)
            std::string h_input = L[i].first +
                                EC_POINT_point2hex(group_, L[i].second.first, POINT_CONVERSION_UNCOMPRESSED, nullptr) +
                                EC_POINT_point2hex(group_, system_public_key_, POINT_CONVERSION_UNCOMPRESSED, nullptr);
            BIGNUM* h_i = hash_[1].hashToBn(h_input);

            // 计算 a_i * (X_i + Y_i + T)
            EC_POINT_add(group_, temp_point, L[i].second.first, L[i].second.second, ctx);  // temp_point = X_i + Y_i
            EC_POINT_add(group_, temp_point, temp_point, T, ctx);  // temp_point = X_i + Y_i + T
            EC_POINT_mul(group_, temp_point, nullptr, temp_point, a_i, ctx);  // temp_point = a_i * (X_i + Y_i + T)
            EC_POINT_add(group_, rhs, rhs, temp_point, ctx);  // 加入到 rhs

            // 计算 (∑_{i=1}^{n} a_i h_i) * P_{pub}
            EC_POINT_mul(group_, temp_point, nullptr, system_public_key_, h_i, ctx);  // temp_point = h_i * P_{pub}
            EC_POINT_mul(group_, temp_point, nullptr, temp_point, a_i, ctx);  // temp_point = a_i * h_i * P_{pub}
            EC_POINT_add(group_, rhs, rhs, temp_point, ctx);  // 累加到 rhs

            BN_free(a_i);
            BN_free(h_i);
        }

        // 计算 ψ * E
        EC_POINT_mul(group_, temp_point, nullptr, E, psi, ctx);  // temp_point = ψ * E
        EC_POINT_add(group_, rhs, rhs, temp_point, ctx);  // 累加到 rhs

         // 计算 (φ + ψ) * P
        BN_mod_add(temp_bn, phi, psi, group_order, ctx);  // temp_bn = φ + ψ
        EC_POINT_mul(group_, temp_point, nullptr, P, temp_bn, ctx);  // temp_point = (φ + ψ) * P
        EC_POINT_add(group_, rhs, rhs, temp_point, ctx);  // 累加到 rhs

        // 验证 ∑_{i=1}^{n} A_i 是否等于右侧计算结果
        bool is_valid = (EC_POINT_cmp(group_, lhs, rhs, ctx) == 0);

        // 清理资源
        EC_POINT_free(lhs);
        EC_POINT_free(rhs);
        EC_POINT_free(E);
        EC_POINT_free(temp_point);
        BN_free(temp_bn);
        BN_CTX_free(ctx);

        return is_valid;
    }

bool Signer::Verify(
    const std::vector<EC_POINT*>& A,
    BIGNUM* phi,
    BIGNUM* psi,
    EC_POINT* T,
    const std::string& msg,
    const std::string& event,
    std::vector<std::pair<std::string, std::pair<EC_POINT*, EC_POINT*>>> ring_pubkeys) {
    
    // 调用私有的verify方法
    return verify(A, phi, psi, T, msg, event, ring_pubkeys);
}

} // namespace ring_signature_lib
