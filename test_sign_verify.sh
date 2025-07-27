#!/bin/bash

echo "=== 环签名生成和验证测试 ==="

# 创建测试消息文件
echo "这是一个测试消息，用于环签名验证。" > test_message.txt

echo "1. 使用signer1生成环签名"
echo "消息: 直接输入的消息"
./build/sign -m "Hello, Ring Signature!" -L "signer1,signer2,signer3" -k "config/signer1_config.json" -o "signature1.json"

echo ""
echo "2. 验证signer1生成的签名"
./build/verify -m "Hello, Ring Signature!" -L "signer1,signer2,signer3" -s "signature1.json"

echo ""
echo "3. 使用signer2生成环签名"
echo "消息: 从文件读取"
./build/sign -m "test_message.txt" -L "signer1,signer2,signer3" -k "config/signer2_config.json" -o "signature2.json"

echo ""
echo "4. 验证signer2生成的签名"
./build/verify -m "test_message.txt" -L "signer1,signer2,signer3" -s "signature2.json"

echo ""
echo "5. 测试错误消息验证（应该失败）"
./build/verify -m "Wrong message!" -L "signer1,signer2,signer3" -s "signature1.json"

echo ""
echo "6. 查看生成的签名文件"
if [ -f "signature1.json" ]; then
    echo "signature1.json 内容:"
    cat signature1.json
else
    echo "signature1.json 未生成"
fi

echo ""
if [ -f "signature2.json" ]; then
    echo "signature2.json 内容:"
    cat signature2.json
else
    echo "signature2.json 未生成"
fi

# 清理测试文件
rm -f test_message.txt signature1.json signature2.json 