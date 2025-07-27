# 环签名程序使用说明

## 概述

`main_sign.cpp` 是一个完整的环签名程序，支持多用户环签名生成。程序会自动构建 `other_key.json` 文件来管理环成员的公钥信息。

## 编译

```bash
mkdir build
cd build
cmake ..
make
```

## 使用方法

### 基本语法

```bash
./sign -m <消息或文件> -L <环列表> -k <key文件> [-o <输出文件>]
```

### 参数说明

- `-m`: 要签名的消息或文件路径
  - 如果提供的是文件路径，程序会读取文件内容作为消息
  - 如果提供的是字符串，程序会直接使用该字符串作为消息
- `-L`: 环成员列表，用逗号分隔的签名者ID (如: signer1,signer2,signer3)
- `-k`: 当前签名者的密钥文件路径
- `-o`: 输出文件路径 (可选，默认输出到屏幕)

### 使用示例

#### 1. 使用直接消息进行签名

```bash
./sign -m "Hello, Ring Signature!" -L "signer1,signer2,signer3" -k "config/signer1_config.json"
```

#### 2. 使用文件消息进行签名并保存到文件

```bash
./sign -m "test_message.txt" -L "signer1,signer2,signer3" -k "config/signer2_config.json" -o "signature_output.json"
```

#### 3. 使用不同签名者进行签名

```bash
# 使用signer1签名
./sign -m "Message from signer1" -L "signer1,signer2" -k "config/signer1_config.json"

# 使用signer2签名
./sign -m "Message from signer2" -L "signer1,signer2" -k "config/signer2_config.json"
```

## 文件结构

### 输入文件

- `config/system_config.json`: 系统配置文件
- `config/signer1_config.json`: signer1的密钥配置
- `config/signer2_config.json`: signer2的密钥配置
- `config/signer3_config.json`: signer3的密钥配置

### 输出文件

- `config/other_key.json`: 自动生成的环成员公钥文件
- `signature_output.json`: 签名结果文件（如果指定了-o参数）

## other_key.json 文件结构

程序会自动生成 `other_key.json` 文件，包含环中其他成员的公钥信息：

```json
{
    "ring_members": [
        {
            "id": "signer1",
            "full_public_key_0": "04...",
            "full_public_key_1": "04..."
        },
        {
            "id": "signer3", 
            "full_public_key_0": "04...",
            "full_public_key_1": "04..."
        }
    ],
    "current_signer": "signer2"
}
```

## 签名输出格式

### 屏幕输出格式

```
=== 环签名结果 ===
A[0]: 04...
A[1]: 04...
phi: ...
psi: ...
T: 04...
```

### 文件输出格式 (JSON)

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

## 错误处理

程序包含完善的错误处理机制：

1. **参数验证**: 检查必需参数是否提供
2. **文件存在性检查**: 验证输入文件是否存在
3. **密钥验证**: 验证签名者密钥是否正确
4. **环成员验证**: 确保环成员数量至少为2
5. **内存管理**: 自动清理OpenSSL对象

## 注意事项

1. 确保所有配置文件都存在且格式正确
2. 环成员列表中的签名者ID必须与配置文件中的ID匹配
3. 当前签名者必须在环成员列表中
4. 程序会自动跳过当前签名者，只加载其他成员的公钥
5. 签名结果包含A数组、phi、psi和T四个部分

## 测试脚本

使用提供的测试脚本可以快速验证程序功能：

```bash
chmod +x test_sign_example.sh
./test_sign_example.sh
``` 