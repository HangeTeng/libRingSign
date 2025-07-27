#include "libringsign/network_utils.h"
#include <stdexcept>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

TCPServer::TCPServer(const std::string& ip, int port) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);
#endif
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) throw std::runtime_error("socket() failed");
    
    // 设置 socket 选项，允许地址重用
    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    // 支持 localhost 和域名解析
    if (ip == "localhost" || ip == "127.0.0.1") {
        addr.sin_addr.s_addr = INADDR_ANY;  // 监听所有接口
    } else {
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            // 尝试域名解析
            struct hostent* host = gethostbyname(ip.c_str());
            if (host == nullptr) {
                throw std::runtime_error("Failed to resolve hostname: " + ip);
            }
            addr.sin_addr.s_addr = *(unsigned long*)host->h_addr_list[0];
        }
    }
    addr.sin_port = htons(port);
    if (bind(server_fd_, (sockaddr*)&addr, sizeof(addr)) < 0)
        throw std::runtime_error("bind() failed");
    if (listen(server_fd_, 5) < 0)
        throw std::runtime_error("listen() failed");
}
TCPServer::~TCPServer() { CloseServer(); }
int TCPServer::Accept() {
    sockaddr_in client_addr{};
    socklen_t len = sizeof(client_addr);
    int client_fd = accept(server_fd_, (sockaddr*)&client_addr, &len);
    if (client_fd < 0) throw std::runtime_error("accept() failed");
    return client_fd;
}
std::string TCPServer::Recv(int client_fd) {
    char buf[4096] = {0};
    int n = recv(client_fd, buf, sizeof(buf)-1, 0);
    if (n <= 0) throw std::runtime_error("recv() failed");
    return std::string(buf, n);
}
void TCPServer::Send(int client_fd, const std::string& msg) {
    int n = send(client_fd, msg.c_str(), (int)msg.size(), 0);
    if (n != (int)msg.size()) throw std::runtime_error("send() failed");
}
void TCPServer::Close(int client_fd) {
#ifdef _WIN32
    closesocket(client_fd);
#else
    close(client_fd);
#endif
}
void TCPServer::CloseServer() {
#ifdef _WIN32
    closesocket(server_fd_);
    WSACleanup();
#else
    close(server_fd_);
#endif
}

TCPClient::TCPClient(const std::string& ip, int port) : ip_(ip), port_(port) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);
#endif
    sock_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd_ < 0) throw std::runtime_error("socket() failed");
}
TCPClient::~TCPClient() { Close(); }
void TCPClient::Connect() {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    // 支持 localhost 和域名解析
    if (ip_ == "localhost" || ip_ == "127.0.0.1") {
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    } else {
        addr.sin_addr.s_addr = inet_addr(ip_.c_str());
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            // 尝试域名解析
            struct hostent* host = gethostbyname(ip_.c_str());
            if (host == nullptr) {
                throw std::runtime_error("Failed to resolve hostname: " + ip_);
            }
            addr.sin_addr.s_addr = *(unsigned long*)host->h_addr_list[0];
        }
    }
    addr.sin_port = htons(port_);
    if (connect(sock_fd_, (sockaddr*)&addr, sizeof(addr)) < 0)
        throw std::runtime_error("connect() failed");
}
void TCPClient::Send(const std::string& msg) {
    int n = send(sock_fd_, msg.c_str(), (int)msg.size(), 0);
    if (n != (int)msg.size()) throw std::runtime_error("send() failed");
}
std::string TCPClient::Recv() {
    char buf[4096] = {0};
    int n = recv(sock_fd_, buf, sizeof(buf)-1, 0);
    if (n <= 0) throw std::runtime_error("recv() failed");
    return std::string(buf, n);
}
void TCPClient::Close() {
#ifdef _WIN32
    closesocket(sock_fd_);
    WSACleanup();
#else
    close(sock_fd_);
#endif
} 