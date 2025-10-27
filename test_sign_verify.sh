#!/bin/bash

# =======================================================
#               公共信息和配置变量
# =======================================================

# 环成员列表 (公钥列表) - 这是环签名的核心公共信息
RING_MEMBERS="signer01,signer02,signer03,signer04,signer05,signer06,signer07,signer08,signer09,signer10,signer11,signer12,signer13,signer14,signer15,signer16,signer17,signer18,signer19,signer20"

# 程序路径
SIGN_EXEC="./build/sign"
VERIFY_EXEC="./build/verify"

# 配置文件目录
CONFIG_DIR="config"

# 测试消息
MESSAGE1="Hello, Ring Signature!"
MESSAGE2="这是一个测试消息，用于环签名验证。"
MESSAGE_FILE="test_message.txt"

# 错误消息，用于测试验证失败的场景
WRONG_MESSAGE="Wrong message!"

# 生成的签名文件
SIGNATURE1_FILE="signature1.json"
SIGNATURE2_FILE="signature2.json"


# =======================================================
#               环签名生成和验证测试
# =======================================================

echo "=== 环签名生成和验证测试 ==="
echo "使用的环成员: $RING_MEMBERS"
echo "-------------------------------------------------------"

# 创建测试消息文件
echo "$MESSAGE2" > "$MESSAGE_FILE"

# --- 测试 1: 使用 signer1 和直接输入的消息 ---
echo "1. 使用 signer1 生成环签名"
echo "   消息: \"$MESSAGE1\""
"$SIGN_EXEC" -m "$MESSAGE1" -L "$RING_MEMBERS" -k "$CONFIG_DIR/signer01_config.json" -o "$SIGNATURE1_FILE"
echo ""

echo "2. 验证 signer1 生成的签名 (应该成功)"
"$VERIFY_EXEC" -m "$MESSAGE1" -L "$RING_MEMBERS" -s "$SIGNATURE1_FILE"
echo "-------------------------------------------------------"


# --- 测试 2: 使用 signer2 和文件消息 ---
echo "3. 使用 signer2 生成环签名"
echo "   消息文件: $MESSAGE_FILE"
"$SIGN_EXEC" -m "$MESSAGE_FILE" -L "$RING_MEMBERS" -k "$CONFIG_DIR/signer02_config.json" -o "$SIGNATURE2_FILE"
echo ""

echo "4. 验证 signer2 生成的签名 (应该成功)"
"$VERIFY_EXEC" -m "$MESSAGE_FILE" -L "$RING_MEMBERS" -s "$SIGNATURE2_FILE"
echo "-------------------------------------------------------"


# --- 测试 3: 错误消息验证 ---
echo "5. 使用错误消息验证签名 (应该失败)"
"$VERIFY_EXEC" -m "$WRONG_MESSAGE" -L "$RING_MEMBERS" -s "$SIGNATURE1_FILE"
echo "-------------------------------------------------------"


# # --- 查看生成的签名文件内容 ---
# echo "6. 查看生成的签名文件"
# if [ -f "$SIGNATURE1_FILE" ]; then
#     echo "   $SIGNATURE1_FILE 内容:"
#     cat "$SIGNATURE1_FILE"
# else
#     echo "   $SIGNATURE1_FILE 未生成"
# fi

# echo ""
# if [ -f "$SIGNATURE2_FILE" ]; then
#     echo "   $SIGNATURE2_FILE 内容:"
#     cat "$SIGNATURE2_FILE"
# else
#     echo "   $SIGNATURE2_FILE 未生成"
# fi
# echo "-------------------------------------------------------"


# --- 清理生成的测试文件 ---
echo "清理测试文件..."
rm -f "$MESSAGE_FILE" "$SIGNATURE1_FILE" "$SIGNATURE2_FILE"
echo "测试完成。"