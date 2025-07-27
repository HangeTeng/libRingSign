#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include "libringsign/signer.h"
#include "libringsign/config_manager.h"

using namespace ring_signature_lib;
using json = nlohmann::json;

void print_usage() {
    std::cout << "用法: ./sign -m <消息或文件> -L <环列表> -k <key文件> [-o <输出文件>]\n";
    std::cout << "参数说明:\n";
    std::cout << "  -m: 要签名的消息或文件路径\n";
    std::cout << "  -L: 环成员列表，用逗号分隔的签名者ID (如: signer1,signer2,signer3)\n";
    std::cout << "  -k: 当前签名者的密钥文件路径\n";
    std::cout << "  -o: 输出文件路径 (可选，默认输出到屏幕)\n";
}

// 读取文件内容
std::string read_file_content(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error("无法打开文件: " + file_path);
    }
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();
    return content;
}

// 将签名结果保存到文件
void save_signature_to_file(const std::string& output_file, 
                           const std::vector<EC_POINT*>& A,
                           BIGNUM* phi, BIGNUM* psi, EC_POINT* T,
                           EC_GROUP* group) {
    json signature_json;
    signature_json["A"] = json::array();
    
    // 保存A数组
    for (size_t i = 0; i < A.size(); ++i) {
        char* point_str = EC_POINT_point2hex(group, A[i], POINT_CONVERSION_UNCOMPRESSED, nullptr);
        signature_json["A"].push_back(point_str);
        OPENSSL_free(point_str);
    }
    
    // 保存phi和psi
    char* phi_str = BN_bn2hex(phi);
    char* psi_str = BN_bn2hex(psi);
    signature_json["phi"] = phi_str;
    signature_json["psi"] = psi_str;
    OPENSSL_free(phi_str);
    OPENSSL_free(psi_str);
    
    // 保存T
    char* t_str = EC_POINT_point2hex(group, T, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    signature_json["T"] = t_str;
    OPENSSL_free(t_str);
    
    // 保存到文件
    std::ofstream file(output_file);
    if (file.is_open()) {
        file << signature_json.dump(4);
        file.close();
        std::cout << "签名已保存到文件: " << output_file << std::endl;
    } else {
        std::cerr << "错误: 无法写入输出文件: " << output_file << std::endl;
    }
}

// 打印签名结果到屏幕
void print_signature(const std::vector<EC_POINT*>& A,
                    BIGNUM* phi, BIGNUM* psi, EC_POINT* T,
                    EC_GROUP* group) {
    std::cout << "\n=== 环签名结果 ===" << std::endl;
    
    // 打印A数组
    for (size_t i = 0; i < A.size(); ++i) {
        char* point_str = EC_POINT_point2hex(group, A[i], POINT_CONVERSION_UNCOMPRESSED, nullptr);
        std::cout << "A[" << i << "]: " << point_str << std::endl;
        OPENSSL_free(point_str);
    }
    
    // 打印phi和psi
    char* phi_str = BN_bn2hex(phi);
    char* psi_str = BN_bn2hex(psi);
    std::cout << "phi: " << phi_str << std::endl;
    std::cout << "psi: " << psi_str << std::endl;
    OPENSSL_free(phi_str);
    OPENSSL_free(psi_str);
    
    // 打印T
    char* t_str = EC_POINT_point2hex(group, T, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    std::cout << "T: " << t_str << std::endl;
    OPENSSL_free(t_str);
}

int main(int argc, char* argv[]) {
    std::string msg_or_file, ring_list, key_file, output_file;
    
    // 解析命令行参数
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            msg_or_file = argv[++i];
        } else if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) {
            ring_list = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        }
    }
    
    // 检查必需参数
    if (msg_or_file.empty() || ring_list.empty() || key_file.empty()) {
        print_usage();
        return 1;
    }
    
    std::cout << "消息/文件: " << msg_or_file << std::endl;
    std::cout << "环列表: " << ring_list << std::endl;
    std::cout << "密钥文件: " << key_file << std::endl;
    if (!output_file.empty()) {
        std::cout << "输出文件: " << output_file << std::endl;
    } else {
        std::cout << "输出到屏幕" << std::endl;
    }
    
    try {
        // 解析环成员列表
        std::vector<std::string> ring_members;
        std::string delimiter = ",";
        size_t pos = 0;
        std::string token;
        std::string ring_list_copy = ring_list;
        
        while ((pos = ring_list_copy.find(delimiter)) != std::string::npos) {
            token = ring_list_copy.substr(0, pos);
            ring_members.push_back(token);
            ring_list_copy.erase(0, pos + delimiter.length());
        }
        ring_members.push_back(ring_list_copy);
        
        if (ring_members.size() < 2) {
            std::cerr << "错误: 环成员数量必须至少为2" << std::endl;
            return 1;
        }
        
        std::cout << "环成员: ";
        for (const auto& member : ring_members) {
            std::cout << member << " ";
        }
        std::cout << std::endl;
        
        // 读取消息内容
        std::string message;
        if (std::filesystem::exists(msg_or_file)) {
            message = read_file_content(msg_or_file);
            std::cout << "从文件读取消息，长度: " << message.length() << " 字符" << std::endl;
        } else {
            message = msg_or_file;
            std::cout << "使用直接输入的消息，长度: " << message.length() << " 字符" << std::endl;
        }
        
        // 从密钥文件确定当前签名者ID
        json key_config = ConfigManager::LoadJson(key_file);
        std::string current_signer_id = key_config["id"];
        std::cout << "当前签名者ID: " << current_signer_id << std::endl;
        
        // 初始化签名者
        Signer signer;
        signer.LoadConfig("config/system_config.json", key_file);
        std::cout << "签名者初始化完成" << std::endl;
        
        // 验证密钥
        if (!signer.VerifyKey()) {
            std::cerr << "错误: 密钥验证失败" << std::endl;
            return 1;
        }
        std::cout << "密钥验证通过" << std::endl;
        
        // 加载环成员的公钥（跳过自己）
        std::vector<std::pair<std::string, std::pair<EC_POINT*, EC_POINT*>>> other_signer_pkc;
        EC_GROUP* group = signer.GetGroup();
        for (const auto& member_id : ring_members) {
            if (member_id == current_signer_id) continue;
            std::string config_path = "config/" + member_id + "_config.json";
            try {
                json member_config = ConfigManager::LoadJson(config_path);
                std::string pub_key_0_hex = member_config["full_public_key_0"];
                std::string pub_key_1_hex = member_config["full_public_key_1"];
                EC_POINT* pub_key_0 = EC_POINT_new(group);
                EC_POINT* pub_key_1 = EC_POINT_new(group);
                if (EC_POINT_hex2point(group, pub_key_0_hex.c_str(), pub_key_0, nullptr) &&
                    EC_POINT_hex2point(group, pub_key_1_hex.c_str(), pub_key_1, nullptr)) {
                    other_signer_pkc.emplace_back(member_id, std::make_pair(pub_key_0, pub_key_1));
                    std::cout << "已加载 " << member_id << " 的公钥" << std::endl;
                } else {
                    std::cerr << "警告: 无法解析 " << member_id << " 的公钥" << std::endl;
                    EC_POINT_free(pub_key_0);
                    EC_POINT_free(pub_key_1);
                }
            } catch (const std::exception& e) {
                std::cerr << "警告: 无法读取 " << member_id << " 的配置: " << e.what() << std::endl;
            }
        }
        
        if (other_signer_pkc.empty()) {
            std::cerr << "错误: 没有找到其他签名者的公钥" << std::endl;
            return 1;
        }
        
        std::cout << "已加载 " << other_signer_pkc.size() << " 个其他签名者的公钥" << std::endl;
        
        // 生成环签名
        std::cout << "开始生成环签名..." << std::endl;
        auto [A, phi, psi, T] = signer.Sign(message, "ring_signature_event", other_signer_pkc);
        
        std::cout << "环签名生成完成!" << std::endl;
        
        // 输出签名结果
        if (!output_file.empty()) {
            save_signature_to_file(output_file, A, phi, psi, T, signer.GetGroup());
        } else {
            print_signature(A, phi, psi, T, signer.GetGroup());
        }
        
        // 清理内存
        for (auto& point : A) {
            EC_POINT_free(point);
        }
        BN_free(phi);
        BN_free(psi);
        EC_POINT_free(T);
        
        for (auto& [id, pub_key_pair] : other_signer_pkc) {
            EC_POINT_free(pub_key_pair.first);
            EC_POINT_free(pub_key_pair.second);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 