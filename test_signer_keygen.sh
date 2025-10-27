#!/bin/bash

# 循环从 1 到 20
for i in $(seq -w 1 20)
do
  # 构造ID和输出文件名
  signer_id="signer${i}"
  output_file="config/signer${i}_config.json"

  # 执行命令
  ./build/keygen -signer -ip "localhost:8080" -id "${signer_id}" -o "${output_file}"

  # 打印日志，方便追踪
  echo "Generated config for ${signer_id} at ${output_file}"
done

echo "All signer configs generated."