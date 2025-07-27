cmake_minimum_required(VERSION 3.10)
project(RingSignatureLib)

set(CMAKE_CXX_STANDARD 17)

# 添加 OpenSSL 库
find_package(OpenSSL REQUIRED)

# 查找 nlohmann/json
find_package(nlohmann_json 3.2.0 QUIET)
if(NOT nlohmann_json_FOUND)
    # 如果找不到系统安装的 nlohmann/json，尝试使用 FetchContent
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# 添加全局头文件搜索路径，便于#include <libringsign/xxx.h>
include_directories(${CMAKE_SOURCE_DIR}/include)

# 添加 hash_utils 源文件
add_library(hash_utils src/hash_utils.cpp)
target_link_libraries(hash_utils OpenSSL::Crypto)

# # 创建 test_hash_utils 测试可执行文件
# add_executable(test_hash_utils tests/test_hash_utils.cpp)
# target_link_libraries(test_hash_utils hash_utils OpenSSL::Crypto)

# 添加 key_generator 源文件
add_library(key_generator src/key_generator.cpp)
target_link_libraries(key_generator OpenSSL::Crypto hash_utils)

# 添加 signer 源文件
add_library(signer src/signer.cpp)
target_link_libraries(signer OpenSSL::Crypto hash_utils key_generator)

# # 创建 key_generator_test 测试可执行文件
# add_executable(test_key_generator tests/test_key_generator.cpp)
# target_link_libraries(test_key_generator key_generator hash_utils OpenSSL::Crypto)

# # 创建 key_agreement_test 测试可执行文件
# add_executable(test_key_agreement tests/test_key_agreement.cpp)
# target_link_libraries(test_key_agreement key_generator signer hash_utils OpenSSL::Crypto)

# # 创建 sign_test 测试可执行文件
# add_executable(test_sign tests/test_sign.cpp)
# target_link_libraries(test_sign signer key_generator hash_utils OpenSSL::Crypto)

# add_executable(test_sign_batch tests/test_sign_batch.cpp)
# target_link_libraries(test_sign_batch signer key_generator hash_utils OpenSSL::Crypto)

# 添加 network_utils 源文件
add_library(network_utils src/network_utils.cpp)

# 添加 config_manager 源文件
add_library(config_manager src/config_manager.cpp)

# 创建 keygen 可执行文件
add_executable(keygen src/main_keygen.cpp)
target_include_directories(keygen PRIVATE include)
target_link_libraries(keygen PRIVATE 
    OpenSSL::Crypto 
    hash_utils 
    key_generator 
    signer 
    network_utils 
    config_manager
    nlohmann_json::nlohmann_json
)

# 在 Windows 下需要链接 ws2_32
if(WIN32)
    target_link_libraries(keygen PRIVATE ws2_32)
endif()

# 创建 sign 可执行文件
add_executable(sign src/main_sign.cpp)
target_include_directories(sign PRIVATE include)
target_link_libraries(sign PRIVATE 
    OpenSSL::Crypto 
    hash_utils 
    key_generator 
    signer 
    network_utils 
    config_manager
    nlohmann_json::nlohmann_json
)

# 补充verify可执行文件
add_executable(verify src/main_verify.cpp)
target_include_directories(verify PRIVATE include)
target_link_libraries(verify PRIVATE 
    OpenSSL::Crypto 
    hash_utils 
    key_generator 
    signer 
    network_utils 
    config_manager
    nlohmann_json::nlohmann_json
)

# 在 Windows 下需要链接 ws2_32
if(WIN32)
    target_link_libraries(verify PRIVATE ws2_32)
endif()