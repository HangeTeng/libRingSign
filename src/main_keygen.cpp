#include <iostream>
#include <string>
#include <cstring>
#include "libringsign/network_utils.h"
#include <nlohmann/json.hpp>
#include "libringsign/key_generator.h"
#include "libringsign/signer.h"
#include <vector>

using nlohmann::json;
using namespace ring_signature_lib;

void print_usage() {
    std::cout << "用法: ./keygen -kgc|-signer -ip <ip:port> [其他参数]\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        print_usage();
        return 1;
    }

    bool is_kgc = false;
    bool is_signer = false;
    std::string ip_port;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-kgc") == 0) {
            is_kgc = true;
        } else if (strcmp(argv[i], "-signer") == 0) {
            is_signer = true;
        } else if (strcmp(argv[i], "-ip") == 0 && i + 1 < argc) {
            ip_port = argv[++i];
        }
    }

    if (!(is_kgc ^ is_signer) || ip_port.empty()) {
        print_usage();
        return 1;
    }

    if (is_kgc) {
        std::cout << "[KGC] 启动密钥中心，监听端口: " << ip_port << std::endl;
        // 解析 ip:port
        auto pos = ip_port.find(":");
        std::string ip = ip_port.substr(0, pos);
        int port = std::stoi(ip_port.substr(pos + 1));
        if (ip == "localhost") ip = "127.0.0.1";

        // 检查是否有-newsys参数
        bool use_newsys = false;
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "-newsys") == 0) {
                use_newsys = true;
                break;
            }
        }

        KeyGenerator keygen;
        if (use_newsys) {
            std::cout << "[KGC] 使用-newsys参数，重新初始化系统密钥并保存到config。" << std::endl;
            keygen.Initialize();
            keygen.SaveConfig("config/system_config.json", "config/system_key.json");
            std::cout << "[KGC] 请注意：系统密钥已更新，请及时发布新的 config/system_config.json 给所有签名者！" << std::endl;
        } else {
            std::cout << "[KGC] 默认从config加载系统密钥。" << std::endl;
            keygen.LoadConfig("config/system_config.json", "config/system_key.json");
        }

        TCPServer server(ip, port);
        std::cout << "[KGC] 等待签名者连接..." << std::endl;
        while (true) {
            int client_fd = server.Accept();
            std::string req = server.Recv(client_fd);
            json j = json::parse(req);
            std::string signer_id = j["id"];
            std::string partial_pub_hex = j["partial_pub"];
            std::cout << "收到签名者: " << signer_id << std::endl;

            // 生成系统部分密钥
            EC_POINT* partial_pub = EC_POINT_new(keygen.GetGroup());
            EC_POINT_hex2point(keygen.GetGroup(), partial_pub_hex.c_str(), partial_pub, nullptr);
            auto [partial_system_pub, partial_priv] = keygen.GenerateSignKey(signer_id, partial_pub);

            char* pub_hex = EC_POINT_point2hex(keygen.GetGroup(), partial_system_pub, POINT_CONVERSION_UNCOMPRESSED, nullptr);
            char* priv_hex = BN_bn2hex(partial_priv);

            // 不再发送系统参数更新，只发送部分密钥
            json resp = { 
                {"partial_system_pub", pub_hex}, 
                {"partial_priv", priv_hex},
                {"update_config", use_newsys ? 1 : 0}
            };

            server.Send(client_fd, resp.dump());
            server.Close(client_fd);

            OPENSSL_free(pub_hex);
            OPENSSL_free(priv_hex);
            EC_POINT_free(partial_pub);
            EC_POINT_free(partial_system_pub);
            BN_free(partial_priv);

            std::cout << "已为签名者 " << signer_id << " 分发系统部分密钥。" << std::endl;
        }
        // server.CloseServer(); // 永久服务，若需退出可加信号处理
    } else if (is_signer) {
        // 解析 -id 参数
        std::string signer_id = "signer1";
        for (int i = 1; i < argc; ++i) {
            if (std::string(argv[i]) == "-id" && i + 1 < argc) {
                signer_id = argv[i + 1];
                break;
            }
        }
        std::cout << "[Signer] 启动签名者 " << signer_id << "，连接到KGC: " << ip_port << std::endl;
        // 解析 ip:port
        auto pos = ip_port.find(":");
        std::string ip = ip_port.substr(0, pos);
        int port = std::stoi(ip_port.substr(pos + 1));
        
        // 处理 localhost
        if (ip == "localhost") {
            ip = "127.0.0.1";
        }

        // 步骤1：初始化签名者，加载系统配置
        Signer signer;
        signer.Initialize(signer_id, "config/system_config.json");

        // 步骤2：生成部分公钥
        auto partial_key = signer.GeneratePartialKey();
        char* partial_pub_hex = EC_POINT_point2hex(signer.GetGroup(), partial_key.second, POINT_CONVERSION_UNCOMPRESSED, nullptr);

        // 步骤3：连接KGC，发送部分公钥和ID
        json req = { {"id", signer_id}, {"partial_pub", partial_pub_hex} };
        TCPClient client(ip, port);
        client.Connect();
        client.Send(req.dump());

        // 步骤4：接收KGC返回的系统部分密钥
        std::string resp_str = client.Recv();
        json resp = json::parse(resp_str);

        EC_POINT* partial_system_pub = EC_POINT_new(signer.GetGroup());
        EC_POINT_hex2point(signer.GetGroup(), resp["partial_system_pub"].get<std::string>().c_str(), partial_system_pub, nullptr);
        BIGNUM* partial_priv = BN_new();
        BN_hex2bn(&partial_priv, resp["partial_priv"].get<std::string>().c_str());

        // 步骤5：生成完整密钥
        signer.GenerateFullKey(partial_system_pub, partial_priv);

        // 步骤7：保存签名者密钥
        std::string output_file = "config/sign_key.json";
        // 检查是否有 -o 参数
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                output_file = argv[i + 1];
                break;
            }
        }
        signer.SaveConfig(output_file);
        std::cout << "签名者 " << signer_id << " 完成密钥协商并保存到 " << output_file << "。" << std::endl;

        OPENSSL_free(partial_pub_hex);
        EC_POINT_free(partial_system_pub);
        BN_free(partial_priv);
        client.Close();
    }

    return 0;
} 