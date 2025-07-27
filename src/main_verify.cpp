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
    std::cout << "用法: ./verify -m <消息或文件> -L <环列表> -s <签名文件>\n";
    std::cout << "参数说明:\n";
    std::cout << "  -m: 要验证的消息或文件路径\n";
    std::cout << "  -L: 环成员列表，用逗号分隔的签名者ID (如: signer1,signer2,signer3)\n";
    std::cout << "  -s: 签名文件 (JSON)\n";
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

int main(int argc, char* argv[]) {
    std::string msg_or_file, ring_list, sig_file;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            msg_or_file = argv[++i];
        } else if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) {
            ring_list = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            sig_file = argv[++i];
        }
    }
    if (msg_or_file.empty() || ring_list.empty() || sig_file.empty()) {
        print_usage();
        return 1;
    }
    std::cout << "消息/文件: " << msg_or_file << std::endl;
    std::cout << "环列表: " << ring_list << std::endl;
    std::cout << "签名文件: " << sig_file << std::endl;

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

        // 加载环成员公钥
        std::vector<std::pair<std::string, std::pair<EC_POINT*, EC_POINT*>>> ring_pubkeys;
        EC_GROUP* group = nullptr;
        for (const auto& member_id : ring_members) {
            std::string config_path = "config/" + member_id + "_config.json";
            try {
                json member_config = ConfigManager::LoadJson(config_path);
                std::string pub_key_0_hex = member_config["full_public_key_0"];
                std::string pub_key_1_hex = member_config["full_public_key_1"];
                if (!group) {
                    // 初始化椭圆曲线群
                    int curve_nid = member_config.value("curve_nid", NID_secp256k1);
                    group = EC_GROUP_new_by_curve_name(curve_nid);
                }
                EC_POINT* pub_key_0 = EC_POINT_new(group);
                EC_POINT* pub_key_1 = EC_POINT_new(group);
                if (EC_POINT_hex2point(group, pub_key_0_hex.c_str(), pub_key_0, nullptr) &&
                    EC_POINT_hex2point(group, pub_key_1_hex.c_str(), pub_key_1, nullptr)) {
                    ring_pubkeys.emplace_back(member_id, std::make_pair(pub_key_0, pub_key_1));
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
        if (!group) {
            std::cerr << "错误: 无法初始化椭圆曲线群" << std::endl;
            return 1;
        }
        if (ring_pubkeys.size() < 2) {
            std::cerr << "错误: 有效环成员公钥数量不足2" << std::endl;
            EC_GROUP_free(group);
            return 1;
        }

        // 读取签名文件
        json sig_json = ConfigManager::LoadJson(sig_file);
        std::vector<EC_POINT*> A;
        for (const auto& a_hex : sig_json["A"]) {
            EC_POINT* a_pt = EC_POINT_new(group);
            if (!EC_POINT_hex2point(group, a_hex.get<std::string>().c_str(), a_pt, nullptr)) {
                std::cerr << "警告: 无法解析A中的点: " << a_hex << std::endl;
                EC_POINT_free(a_pt);
                continue;
            }
            A.push_back(a_pt);
        }
        BIGNUM* phi = nullptr;
        BIGNUM* psi = nullptr;
        EC_POINT* T = nullptr;
        BN_hex2bn(&phi, sig_json["phi"].get<std::string>().c_str());
        BN_hex2bn(&psi, sig_json["psi"].get<std::string>().c_str());
        T = EC_POINT_new(group);
        if (!EC_POINT_hex2point(group, sig_json["T"].get<std::string>().c_str(), T, nullptr)) {
            std::cerr << "错误: 无法解析签名T点" << std::endl;
            EC_POINT_free(T);
            T = nullptr;
        }

        // 验证签名
        Signer verifier;
        // 需要初始化系统配置以获取群参数和哈希函数
        verifier.LoadConfig("config/system_config.json");
        bool valid = verifier.Verify(A, phi, psi, T, message, "ring_signature_event", ring_pubkeys);
        if (valid) {
            std::cout << "\n签名验证通过！" << std::endl;
        } else {
            std::cout << "\n签名验证失败！" << std::endl;
        }

        // 清理内存
        for (auto& pt : A) EC_POINT_free(pt);
        BN_free(phi);
        BN_free(psi);
        if (T) EC_POINT_free(T);
        for (auto& [id, pub_pair] : ring_pubkeys) {
            EC_POINT_free(pub_pair.first);
            EC_POINT_free(pub_pair.second);
        }
        EC_GROUP_free(group);
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
    return 0;
} 