cmake_minimum_required(VERSION 3.10)
project(RingSignatureLib)

set(CMAKE_CXX_STANDARD 17)

# 添加 OpenSSL 库
find_package(OpenSSL REQUIRED)

# 添加全局头文件搜索路径，便于#include <libringsign/xxx.h>
include_directories(${CMAKE_SOURCE_DIR}/include)

# 添加 hash_utils 源文件
add_library(hash_utils src/hash_utils.cpp)
target_link_libraries(hash_utils OpenSSL::Crypto)

# 创建 test_hash_utils 测试可执行文件
add_executable(test_hash_utils tests/test_hash_utils.cpp)
target_link_libraries(test_hash_utils hash_utils OpenSSL::Crypto)

# 添加 key_generator 源文件
add_library(key_generator src/key_generator.cpp)
target_link_libraries(key_generator OpenSSL::Crypto hash_utils)

# 添加 signer 源文件
add_library(signer src/signer.cpp)
target_link_libraries(signer OpenSSL::Crypto hash_utils key_generator)

# 创建 key_generator_test 测试可执行文件
add_executable(test_key_generator tests/test_key_generator.cpp)
target_link_libraries(test_key_generator key_generator hash_utils OpenSSL::Crypto)

# 创建 key_agreement_test 测试可执行文件
add_executable(test_key_agreement tests/test_key_agreement.cpp)
target_link_libraries(test_key_agreement key_generator signer hash_utils OpenSSL::Crypto)

# 创建 sign_test 测试可执行文件
add_executable(test_sign tests/test_sign.cpp)
target_link_libraries(test_sign signer key_generator hash_utils OpenSSL::Crypto)

add_executable(test_sign_batch tests/test_sign_batch.cpp)
target_link_libraries(test_sign_batch signer key_generator hash_utils OpenSSL::Crypto)