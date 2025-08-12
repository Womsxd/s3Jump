#!/bin/bash

# 固定节点名称
NODE_NAME="node1"
# 节点密钥，需与服务端配置一致
NODE_SECRET="your-node-secret"
# 网络接口名称，用户可根据实际情况修改
INTERFACE="eth0"

# 测量时间间隔（秒）
INTERVAL=1

# 获取上传带宽函数，返回bps
get_upload_bps() {
    local start_bytes=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)
    local start_time=$(date +%s)
    sleep $INTERVAL
    local end_bytes=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)
    local end_time=$(date +%s)
    local byte_diff=$((end_bytes - start_bytes))
    local time_diff=$((end_time - start_time))
    echo $((byte_diff * 8 / time_diff))
}

# 调用函数获取bps
bps=$(get_upload_bps)

# 转换为mbps，保留一位小数
mbps=$(echo "scale=2; $bps / 1000000" | bc)

# 如果mbps以点开头，补0
if [[ $mbps == .* ]]; then
    mbps="0$mbps"
fi

# 计算时间戳和HMAC
timestamp=$(date +%s)
message="${NODE_NAME}|${mbps}|${timestamp}"
hmac=$(echo -n "$message" | openssl dgst -sha256 -hmac "$NODE_SECRET" | sed 's/^.* //')

auth_token="${timestamp},${hmac}"

# 发送POST请求上传带宽数据，带鉴权头
curl -X POST http://localhost:8000/report-bandwidth \
    -H "Content-Type: application/json" \
    -H "X-Auth-Token: $auth_token" \
    -d "{\"node_name\":\"$NODE_NAME\", \"now_bandwidth\":$mbps}"

