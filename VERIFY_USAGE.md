# 环签名验证程序使用说明

## 概述

`main_verify.cpp` 是一个完整的环签名验证程序，用于验证由 `main_sign.cpp` 生成的环签名。程序支持验证多用户环签名的有效性。

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
./verify -m <消息或文件> -L <环列表> -s <签名文件>
```

### 参数说明

- `-m`: 要验证的消息或文件路径
  - 如果提供的是文件路径，程序会读取文件内容作为消息
  - 如果提供的是字符串，程序会直接使用该字符串作为消息
- `-L`: 环成员列表，用逗号分隔的签名者ID (如: signer1,signer2,signer3)
- `-s`: 签名文件路径 (JSON格式)

### 使用示例

#### 1. 验证直接消息的签名

```bash
./verify -m "Hello, Ring Signature!" -L "signer1,signer2,signer3" -s "signature.json"
```

#### 2. 验证文件消息的签名

```bash
./verify -m "test_message.txt" -L "signer1,signer2,signer3" -s "signature.json"
```

#### 3. 验证不同环成员的签名

```bash
# 验证包含signer1和signer2的环签名
./verify -m "Message" -L "signer1,signer2" -s "signature.json"

# 验证包含signer1、signer2和signer3的环签名
./verify -m "Message" -L "signer1,signer2,signer3" -s "signature.json"
```

## 签名文件格式

验证程序期望的签名文件格式（JSON）：

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

其中：
- `A`: 签名点数组，每个元素是十六进制格式的椭圆曲线点
- `phi`: 签名的phi值，十六进制格式
- `psi`: 签名的psi值，十六进制格式
- `T`: 签名的T点，十六进制格式

## 验证结果

程序会输出以下结果之一：

- **签名验证通过！**: 签名有效
- **签名验证失败！**: 签名无效

## 错误处理

程序包含完善的错误处理机制：

1. **参数验证**: 检查必需参数是否提供
2. **文件存在性检查**: 验证输入文件是否存在
3. **环成员验证**: 确保环成员数量至少为2
4. **签名格式验证**: 检查签名文件的JSON格式和内容
5. **公钥加载验证**: 确保能正确加载所有环成员的公钥
6. **内存管理**: 自动清理OpenSSL对象

## 注意事项

1. 确保所有环成员的配置文件都存在且格式正确
2. 环成员列表中的签名者ID必须与配置文件中的ID匹配
3. 验证时使用的消息必须与签名时使用的消息完全一致
4. 验证时使用的环成员列表必须与签名时使用的环成员列表一致
5. 签名文件必须是有效的JSON格式

## 完整测试流程

使用提供的测试脚本可以验证完整的签名和验证流程：

```bash
chmod +x test_sign_verify.sh
./test_sign_verify.sh
```

这个脚本会：
1. 生成环签名
2. 验证正确的签名
3. 测试错误消息的验证（应该失败）
4. 显示生成的签名文件内容

## 与签名程序的配合

验证程序与签名程序配合使用：

```bash
# 1. 生成签名
./sign -m "Hello" -L "signer1,signer2,signer3" -k "config/signer1_config.json" -o "signature.json"

# 2. 验证签名
./verify -m "Hello" -L "signer1,signer2,signer3" -s "signature.json"
```

## 技术细节

- 使用OpenSSL库进行椭圆曲线运算
- 支持多种椭圆曲线（通过配置文件指定）
- 自动处理OpenSSL对象的内存管理
- 使用nlohmann/json库处理JSON格式
- 支持文件系统和直接字符串输入 