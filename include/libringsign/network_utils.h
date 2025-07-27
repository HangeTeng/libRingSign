#pragma once
#include <string>

class TCPServer {
public:
    TCPServer(const std::string& ip, int port);
    ~TCPServer();
    int Accept(); // 返回已连接的socket fd
    std::string Recv(int client_fd);
    void Send(int client_fd, const std::string& msg);
    void Close(int client_fd);
    void CloseServer();
private:
    int server_fd_;
};

class TCPClient {
public:
    TCPClient(const std::string& ip, int port);
    ~TCPClient();
    void Connect();
    void Send(const std::string& msg);
    std::string Recv();
    void Close();
private:
    int sock_fd_;
    std::string ip_;
    int port_;
}; 