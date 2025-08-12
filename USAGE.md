# libRingSign 环签名库使用说明

## 概述

libRingSign 是一个完整的环签名系统，包含密钥生成中心(KGC)、签名者和验证者三个主要组件。系统支持多用户环签名生成和验证，提供完整的密钥管理和网络通信功能。

## 系统架构

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    KGC      │    │   Signer    │    │  Verifier   │
│ (密钥中心)   │◄──►│  (签名者)   │    │  (验证者)   │
└─────────────┘    └─────────────┘    └─────────────┘
```

## 编译

```bash
# 创建构建目录
mkdir build
cd build

# 配置和编译
cmake ..
make

# 返回根目录
cd ..
```

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

### 密钥生成中心 (KGC)

#### 功能
- 管理系统的全局参数和密钥
- 为签名者生成部分密钥
- 提供网络服务接口

#### 启动方式

```bash
./build/keygen -kgc -ip <IP:端口> [-newsys]
```

#### 参数说明
- `-kgc`: 以KGC模式运行
- `-ip <IP:端口>`: 指定监听地址和端口
- `-newsys`: 重新初始化系统密钥（可选）

#### 使用示例

```bash
# 使用默认配置启动
./build/keygen -kgc -ip "localhost:8080"

# 重新初始化系统密钥
./build/keygen -kgc -ip "localhost:8080" -newsys
```

#### 注意事项
- KGC启动后会持续运行，等待签名者连接
- 使用 `-newsys` 参数会更新系统密钥，需要重新分发给所有签名者
- 建议在生产环境中使用真实的IP地址而不是localhost

### 签名者密钥生成

#### 功能
- 连接到KGC进行密钥协商
- 生成完整的签名密钥对
- 保存密钥配置到文件

#### 使用方式

```bash
./build/keygen -signer -ip <KGC_IP:端口> -id <签名者ID> [-o <输出文件>]
```

#### 参数说明
- `-signer`: 以签名者模式运行
- `-ip <KGC_IP:端口>`: KGC的地址和端口
- `-id <签名者ID>`: 签名者的唯一标识符
- `-o <输出文件>`: 密钥配置文件输出路径（可选，默认为config/sign_key.json）

#### 使用示例

```bash
# 生成signer1的密钥
./build/keygen -signer -ip "localhost:8080" -id "signer1" -o "config/signer1_config.json"

# 生成signer2的密钥
./build/keygen -signer -ip "localhost:8080" -id "signer2" -o "config/signer2_config.json"

# 生成signer3的密钥
./build/keygen -signer -ip "localhost:8080" -id "signer3" -o "config/signer3_config.json"
```

#### 密钥协商流程
1. 签名者初始化并加载系统配置
2. 生成部分公钥
3. 连接KGC并发送部分公钥和ID
4. 接收KGC返回的系统部分密钥
5. 生成完整密钥对
6. 保存密钥配置到文件

### 环签名生成

#### 功能
- 生成多用户环签名
- 支持直接消息和文件消息
- 自动管理环成员公钥

#### 使用方式

```bash
./build/sign -m <消息或文件> -L <环列表> -k <密钥文件> [-o <输出文件>]
```

#### 参数说明
- `-m`: 要签名的消息或文件路径
  - 如果提供文件路径，程序会读取文件内容作为消息
  - 如果提供字符串，程序会直接使用该字符串作为消息
- `-L`: 环成员列表，用逗号分隔的签名者ID
- `-k`: 当前签名者的密钥文件路径
- `-o`: 输出文件路径（可选，默认输出到屏幕）

#### 使用示例

```bash
# 使用直接消息进行签名
./build/sign -m "Hello, Ring Signature!" -L "signer1,signer2,signer3" -k "config/signer1_config.json"

# 使用文件消息进行签名并保存到文件
./build/sign -m "test_message.txt" -L "signer1,signer2,signer3" -k "config/signer2_config.json" -o "signature_output.json"

# 使用不同签名者进行签名
./build/sign -m "Message from signer1" -L "signer1,signer2" -k "config/signer1_config.json"
./build/sign -m "Message from signer2" -L "signer1,signer2" -k "config/signer2_config.json"
```

#### 输出格式

**屏幕输出格式：**
```
=== 环签名结果 ===
A[0]: 04...
A[1]: 04...
phi: ...
psi: ...
T: 04...
```

**文件输出格式 (JSON)：**
```json
{
    "A": [
        "04...",
        "04..."
    ],
    "phi": "...",
    "psi": "...", 
    "T": "04..."
}
```

### 环签名验证

#### 功能
- 验证环签名的有效性
- 支持直接消息和文件消息验证
- 验证环成员公钥的正确性

#### 使用方式

```bash
./build/verify -m <消息或文件> -L <环列表> -s <签名文件>
```

#### 参数说明
- `-m`: 要验证的消息或文件路径
- `-L`: 环成员列表，用逗号分隔的签名者ID
- `-s`: 签名文件路径（JSON格式）

#### 使用示例

```bash
# 验证直接消息的签名
./build/verify -m "Hello, Ring Signature!" -L "signer1,signer2,signer3" -s "signature.json"

# 验证文件消息的签名
./build/verify -m "test_message.txt" -L "signer1,signer2,signer3" -s "signature.json"

# 验证不同环成员的签名
./build/verify -m "Message" -L "signer1,signer2" -s "signature.json"
```

#### 验证结果
- **签名验证通过！**: 签名有效
- **签名验证失败！**: 签名无效

## 文件结构

### 配置文件

#### 系统配置文件 (config/system_config.json)
```json
{
    "curve_nid": 714,
    "hash_keys": [
        "hash_key_1712704830",
        "hash_key_504980295",
        "hash_key_1685559299",
        "hash_key_1895190489",
        "hash_key_331010105"
    ],
    "hash_type": "SHA256",
    "system_public_key": "043E8B3F56F25589DFCC6552DCB40CDB3C119699FAE4F24649E30616F43B2D5CD096A6884B7A26A41FA368F515EA34CB31B0BFC29579C5EAEBD6F765DD81D6989D"
}
```

#### 签名者配置文件 (config/signer1_config.json)
```json
{
    "id": "signer1",
    "full_public_key_0": "042BE478F290ECC68E79350D3C203F4D90E0A78145077C972680675CC1707DF09A266B9C4EC4E2215C552311FF573AEEA04AD8F0773D784EE76C2C13677FE5D2C8",
    "full_public_key_1": "04A3906CA18CAB93A6F82BCC93AD56D67F9469E8F850F7C8A3482FC7994F98C13510E93C0ABDB5CA586B30269C7EA590A443ACDAC9A163B93E1CC4393B3FA1447D",
    "partial_private_key": "19697CB721C15F16A0EFDFA8078897D5A2016D59A6B9BF8D5AB3CA2E1B58BEAD841AE4ED32929E16EB9F74ECF57C52D30E59A6F19513EC4635C9B7D72030BFC0",
    "private_key": "416CE2154A90DF9F5EE43BBDCF5D97D74353693FABADE6D5AB4AF72A8C182941"
}
```

#### 签名文件格式
```json
{
    "A": [
        "04...",
        "04..."
    ],
    "phi": "...",
    "psi": "...", 
    "T": "04..."
}
```

## 完整工作流程示例

### 1. 系统初始化

```bash
# 启动KGC（重新初始化系统密钥）
./build/keygen -kgc -ip "localhost:8080" -newsys
```

### 2. 生成签名者密钥

```bash
# 在另一个终端中生成signer1的密钥
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

## 测试脚本

### 快速测试

```bash
# 运行完整的签名和验证测试
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

## 错误处理

系统包含完善的错误处理机制：

1. **参数验证**: 检查必需参数是否提供
2. **文件存在性检查**: 验证输入文件是否存在
3. **网络连接检查**: 验证KGC和签名者之间的连接
4. **密钥验证**: 验证签名者密钥是否正确
5. **环成员验证**: 确保环成员数量至少为2
6. **签名格式验证**: 检查签名文件的JSON格式和内容
7. **内存管理**: 自动清理OpenSSL对象

## 注意事项

### 安全性
1. 确保所有配置文件都存在且格式正确
2. 环成员列表中的签名者ID必须与配置文件中的ID匹配
3. 当前签名者必须在环成员列表中
4. 验证时使用的消息必须与签名时使用的消息完全一致
5. 验证时使用的环成员列表必须与签名时使用的环成员列表一致

### 网络配置
1. 确保KGC和签名者之间的网络连接正常
2. 在生产环境中使用真实的IP地址
3. 配置适当的防火墙规则

### 密钥管理
1. 定期更新系统密钥
2. 安全存储签名者密钥文件
3. 备份重要的配置文件

## 技术细节

- 使用OpenSSL库进行椭圆曲线运算
- 支持多种椭圆曲线（通过配置文件指定）
- 使用TCP协议进行KGC和签名者之间的通信
- 使用nlohmann/json库处理JSON格式
- 支持文件系统和直接字符串输入
- 自动处理OpenSSL对象的内存管理

## 故障排除

### 常见问题

1. **编译错误**: 确保已安装OpenSSL和nlohmann/json库
2. **网络连接失败**: 检查KGC是否正在运行，IP地址和端口是否正确
3. **密钥生成失败**: 确保系统配置文件存在且格式正确
4. **签名验证失败**: 检查消息、环成员列表和签名文件是否一致

### 调试技巧

1. 使用 `-o` 参数保存输出文件以便检查
2. 检查生成的JSON文件格式是否正确
3. 验证网络连接和端口配置
4. 查看程序输出的详细错误信息
