cmake_minimum_required(VERSION 3.10)
project(RingSignatureLib)

set(CMAKE_CXX_STANDARD 17)

# 添加 OpenSSL 库
find_package(OpenSSL REQUIRED)

# 添加 hash 源文件
add_library(hash src/hash.cpp)
target_link_libraries(hash OpenSSL::Crypto)

# 添加 key_generator 源文件
add_library(key_generator src/key_generator.cpp)
target_link_libraries(key_generator OpenSSL::Crypto hash)

# 添加 signer 源文件
add_library(signer src/signer.cpp)
target_link_libraries(signer OpenSSL::Crypto hash key_generator)

# 创建 hash_test 测试可执行文件
add_executable(hash_test src/hash_test.cpp)
target_link_libraries(hash_test hash OpenSSL::Crypto)

# 创建 key_generator_test 测试可执行文件
add_executable(key_generator_test src/key_generator_test.cpp)
target_link_libraries(key_generator_test key_generator hash OpenSSL::Crypto)

# 创建 key_agreement_test 测试可执行文件
add_executable(key_agreement_test src/key_agreement_test.cpp)
target_link_libraries(key_agreement_test key_generator signer hash OpenSSL::Crypto)

# 创建 sign_test 测试可执行文件
add_executable(sign_test src/sign_test.cpp)
target_link_libraries(sign_test signer key_generator hash OpenSSL::Crypto)

add_executable(sign_batch_test src/sign_batch_test.cpp)
target_link_libraries(sign_batch_test signer key_generator hash OpenSSL::Crypto)