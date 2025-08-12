# libRingSign

libRingSign 是一个基于C++和OpenSSL的完整环签名系统，实现了密钥生成中心(KGC)、签名者和验证者三个主要组件。系统支持多用户环签名生成和验证，提供完整的密钥管理和网络通信功能，确保高等级的隐私保护。

## 特性

- **完整的环签名系统**：包含KGC、签名者和验证者三个组件
- **网络通信支持**：KGC和签名者之间通过TCP协议进行密钥协商
- **多用户环签名**：支持任意数量的环成员进行签名
- **密钥管理**：自动化的密钥生成和分发机制
- **文件支持**：支持直接消息和文件消息的签名和验证
- **JSON配置**：使用JSON格式进行配置管理和签名输出
- **模块化设计**：各个功能模块分离，便于扩展和维护
- **基于OpenSSL**：利用OpenSSL库提供安全的加密支持
- **完整测试**：包含独立的测试文件和自动化测试脚本

## 系统架构

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    KGC      │    │   Signer    │    │  Verifier   │
│ (密钥中心)   │◄──►│  (签名者)   │    │  (验证者)   │
└─────────────┘    └─────────────┘    └─────────────┘
```

- **KGC (Key Generation Center)**：管理系统的全局参数和密钥，为签名者生成部分密钥
- **Signer (签名者)**：连接到KGC进行密钥协商，生成环签名
- **Verifier (验证者)**：验证环签名的有效性

## 项目结构

```plaintext
├── src/
│   ├── main_keygen.cpp           # 密钥生成中心主程序
│   ├── main_sign.cpp             # 环签名生成主程序
│   ├── main_verify.cpp           # 环签名验证主程序
│   ├── signer.cpp                # 环签名核心逻辑实现
│   ├── config_manager.cpp        # 配置管理模块实现
│   ├── hash_utils.cpp            # 哈希工具函数实现
│   ├── key_generator.cpp         # 密钥生成模块实现
│   └── network_utils.cpp         # 网络通信工具实现
│
├── include/
│   └── libringsign/
│       ├── signer.h              # 环签名核心逻辑头文件
│       ├── config_manager.h      # 配置管理模块头文件
│       ├── hash_utils.h          # 哈希工具函数头文件
│       ├── key_generator.h       # 密钥生成模块头文件
│       └── network_utils.h       # 网络通信工具头文件
│
├── config/
│   ├── system_config.json        # 系统配置文件
│   ├── system_key.json           # 系统密钥配置
│   ├── signer1_config.json       # 签名者1配置
│   ├── signer2_config.json       # 签名者2配置
│   ├── signer3_config.json       # 签名者3配置
│   └── other_key.json            # 环成员公钥文件
│
├── tests/
│   ├── test_hash_utils.cpp       # 哈希工具测试
│   ├── test_key_agreement.cpp    # 密钥协商测试
│   ├── test_key_generator.cpp    # 密钥生成测试
│   ├── test_sign_batch.cpp       # 批量签名测试
│   └── test_sign.cpp             # 签名功能测试
│
├── scripts/
│   ├── plot_sign_batch_time.py   # 签名批量时间绘图脚本
│   └── result.py                 # 结果处理脚本
│
├── CMakeLists.txt                # CMake构建脚本
├── README.md                     # 项目说明文件
├── USAGE.md                      # 详细使用说明文档
├── SIGN_USAGE.md                 # 签名功能使用说明
├── VERIFY_USAGE.md               # 验证功能使用说明
├── rebuild_test.sh               # 测试重建脚本
└── test_sign_verify.sh           # 签名验证测试脚本
```

## 依赖

- **C++ 17** 或更高版本
- **OpenSSL**：用于加密和哈希函数支持
- **nlohmann/json**：用于JSON格式处理

### 安装依赖（以Ubuntu为例）

```bash
sudo apt update
sudo apt install libssl-dev nlohmann-json3-dev
```

## 安装和编译

### 使用CMake进行构建

1. 克隆此仓库：

    ```bash
    git clone https://github.com/yourusername/libringsig.git
    cd libringsig
    ```

2. 创建并进入构建目录：

    ```bash
    mkdir build
    cd build
    ```

3. 运行CMake以生成构建文件：

    ```bash
    cmake ..
    ```

4. 编译项目：

    ```bash
    make
    ```

成功编译后，将会生成以下可执行文件：

- `keygen`：密钥生成中心程序
- `sign`：环签名生成程序
- `verify`：环签名验证程序
- 各种测试程序

## 快速开始

### 1. 启动密钥生成中心 (KGC)

```bash
# 使用默认系统配置启动KGC
./build/keygen -kgc -ip "localhost:8080"

# 重新初始化系统密钥并启动KGC
./build/keygen -kgc -ip "localhost:8080" -newsys
```

### 2. 生成签名者密钥

```bash
# 生成signer1的密钥
./build/keygen -signer -ip "localhost:8080" -id "signer1" -o "config/signer1_config.json"

# 生成signer2的密钥
./build/keygen -signer -ip "localhost:8080" -id "signer2" -o "config/signer2_config.json"

# 生成signer3的密钥
./build/keygen -signer -ip "localhost:8080" -id "signer3" -o "config/signer3_config.json"
```

### 3. 生成环签名

```bash
# 使用signer1生成环签名
./build/sign -m "Hello, Ring Signature!" -L "signer1,signer2,signer3" -k "config/signer1_config.json" -o "signature.json"
```

### 4. 验证环签名

```bash
# 验证环签名
./build/verify -m "Hello, Ring Signature!" -L "signer1,signer2,signer3" -s "signature.json"
```

## 详细使用说明

请参考 [USAGE.md](USAGE.md) 文档获取详细的使用说明，包括：

- 完整的参数说明和使用示例
- 配置文件格式说明
- 网络配置和故障排除
- 安全注意事项
- 完整工作流程示例

## 测试

### 运行完整测试

```bash
# 运行签名和验证测试
chmod +x test_sign_verify.sh
./test_sign_verify.sh
```

### 重新构建和测试

```bash
# 重新构建项目并运行测试
chmod +x rebuild_test.sh
./rebuild_test.sh
chmod +x test_sign_verify.sh
./test_sign_verify.sh
```

### 各测试文件说明

- **`test_sign_verify.sh`**：完整的签名和验证流程测试
- **`test_sign.cpp`**：环签名生成和验证功能测试
- **`test_key_generator.cpp`**：密钥生成模块测试
- **`test_hash_utils.cpp`**：哈希工具函数测试
- **`test_key_agreement.cpp`**：密钥协商逻辑测试
- **`test_sign_batch.cpp`**：批量签名性能测试

## 配置选项

系统支持多种配置选项：

- **椭圆曲线**：通过配置文件指定椭圆曲线类型
- **哈希算法**：可配置使用的哈希算法
- **网络参数**：可自定义KGC的监听地址和端口
- **密钥管理**：支持系统密钥的重新初始化

## 技术特性

- **椭圆曲线密码学**：基于OpenSSL的椭圆曲线运算
- **TCP网络通信**：KGC和签名者之间的安全通信
- **JSON数据格式**：使用nlohmann/json库处理配置和签名数据
- **内存管理**：自动处理OpenSSL对象的内存管理
- **错误处理**：完善的错误处理和验证机制

## 安全特性

- **匿名性**：环签名确保签名者的身份匿名性
- **不可伪造性**：防止未授权用户生成有效签名
- **不可链接性**：同一签名者的不同签名无法被关联
- **密钥管理**：安全的密钥生成和分发机制

## 扩展功能

### 自定义哈希算法

用户可以通过修改 `hash_utils.cpp` 和 `hash_utils.h` 文件来实现自定义哈希算法。

### 增加支持的密钥类型

可以在 `key_generator.cpp` 中对密钥生成逻辑进行扩展，支持更多类型的椭圆曲线。

### 网络协议扩展

可以扩展 `network_utils.cpp` 来支持更复杂的网络通信协议和安全机制。

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 联系方式

如有问题或建议，请通过GitHub Issues联系我们。