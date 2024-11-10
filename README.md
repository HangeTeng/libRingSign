# LibringSig

LibringSig 是一个基于C++和OpenSSL的环签名库，主要用于实现环签名的生成和验证功能。环签名是一种特殊的数字签名，它允许签名者通过一个匿名群体进行签名，提供高等级的隐私保护。

## 特性

- **支持环签名的生成和验证**：提供环签名的核心实现。
- **包含密钥生成功能**：通过`key_generator`模块生成密钥对。
- **模块化设计，方便扩展**：各个功能模块分离，便于后续的功能拓展。
- **基于OpenSSL的加密支持**：利用OpenSSL库增强安全性。
- **测试文件**：包含独立的测试文件，便于验证各模块功能。

## 项目结构

```plaintext
├── src/
│   ├── signer.cpp / signer.h           # 环签名核心逻辑
│   ├── config.h                        # 配置文件，包含全局常量和设置
│   ├── hash.cpp / hash.h               # 哈希模块，实现签名算法中的哈希功能
│   ├── key_generator.cpp / key_generator.h  # 密钥生成模块
│   ├── sign_test.cpp                   # 签名测试文件，验证签名和密钥生成功能
│
├── CMakeLists.txt                      # CMake构建脚本
└── README.md                           # 项目说明文件
```

## 依赖

- **C++ 17** 或更高版本
- **OpenSSL**：用于加密和哈希函数支持

在安装项目之前，请确保安装了这些依赖。

### OpenSSL安装指引（以Ubuntu为例）

```bash
sudo apt update
sudo apt install libssl-dev
```

## 安装

### 使用CMake进行构建

1. 克隆此仓库：

    ```bash
    git clone https://github.com/yourusername/libringsig.git
    ```

2. 进入项目目录：

    ```bash
    cd libringsig
    ```

3. 创建并进入构建目录：

    ```bash
    mkdir build
    cd build
    ```

4. 运行CMake以生成构建文件：

    ```bash
    cmake ..
    ```

5. 编译项目：

    ```bash
    make
    ```

成功编译后，将会生成以下可执行文件：

- `sign_test`
- `key_generator_test`
- `hash_test`
- `key_agreement_test`

## 使用示例

### 签名生成与验证

`signer.cpp`实现了生成和验证环签名的核心逻辑，以下是调用示例：

```cpp
#include "signer.h"
#include "key_generator.h"
#include "hash.h"

int main() {
    KeyGenerator keyGen;
    Signer signer;

    // 生成密钥对
    auto keyPair = keyGen.generateKeyPair();

    // 生成签名
    std::string message = "This is a secret message.";
    auto signature = signer.sign(message, keyPair);

    // 验证签名
    bool isValid = signer.verify(message, signature, keyPair.publicKey);
    if (isValid) {
        std::cout << "Signature is valid." << std::endl;
    } else {
        std::cout << "Signature is invalid." << std::endl;
    }

    return 0;
}
```

### 各测试文件说明

- **`sign_test`**：用于验证签名生成和验证过程。
    ```bash
    ./sign_test
    ```
- **`key_generator_test`**：用于测试密钥生成模块。
    ```bash
    ./key_generator_test
    ```
- **`hash_test`**：用于测试自定义哈希函数的正确性。
    ```bash
    ./hash_test
    ```
- **`key_agreement_test`**：测试密钥协商的逻辑。
    ```bash
    ./key_agreement_test
    ```

### 配置选项

在`config.h`中可以自定义一些全局配置：

- **椭圆曲线**：可配置椭圆曲线类型
- **哈希算法**：可更改使用的哈希算法

修改`config.h`文件中的配置项即可完成个性化定制。

## 可选功能扩展

### 自定义哈希算法

用户可以通过修改`hash.cpp`和`hash.h`文件来实现自定义哈希算法。例如，如果您希望使用SHA-256以外的算法，可以在`hash.cpp`中导入相应的OpenSSL库函数。

### 增加支持的密钥类型

当前的`key_generator`模块默认生成的密钥类型为ECC。可以在`key_generator.cpp`中对密钥生成逻辑进行扩展，并在`CMakeLists.txt`中添加相应的OpenSSL依赖。



apt-get install nlohmann-json3-dev