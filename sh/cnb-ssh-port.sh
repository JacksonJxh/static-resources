#!/bin/bash

# --- 配置项：优先使用环境变量，未设置则使用默认值 ---
PRIVATE_REGISTRY="${PRIVATE_REGISTRY:-docker.cnb.cool}"

TAILSCALE_ENABLED="${TAILSCALE_ENABLED:-true}"


# --- 基础环境检查 ---
if ! command -v docker &> /dev/null; then
  echo "错误：未安装Docker，无法启动容器"
  exit 1
fi

if ! docker info &> /dev/null; then
  echo "错误：Docker服务未运行，请先启动Docker"
  exit 1
fi

# --- Tailscale 用户模式启动 ---
start_tailscale_userspace() {
    if [ "$TAILSCALE_ENABLED" != "true" ]; then
        echo "Tailscale 未启用 (TAILSCALE_ENABLED=$TAILSCALE_ENABLED)，跳过启动"
        return
    fi

    if [ -z "$TAILSCALE_AUTHKEY" ]; then
        echo "警告：未设置 TAILSCALE_AUTHKEY，跳过 Tailscale 启动"
        return
    fi

    echo "正在启动 Tailscale 用户模式..."

    if ! command -v tailscale &> /dev/null; then
        echo "错误：未安装 tailscale，请先安装"
        return
    fi

    if ! command -v tailscaled &> /dev/null; then
        echo "错误：未安装 tailscaled，请先安装"
        return
    fi

    pkill tailscaled 2>/dev/null || true

    mkdir -p /var/run/tailscale
    mkdir -p /var/cache/tailscale
    mkdir -p /var/lib/tailscale

    tailscaled \
        --tun=userspace-networking \
        --socks5-server=0.0.0.0:1055 \
        --state=mem: > /dev/null 2>&1 &

    sleep 3

    tailscale up \
        --authkey="${TAILSCALE_AUTHKEY}" \
        --login-server="${TAILSCALE_LOGIN_SERVER}" \
        --hostname="${TAILSCALE_HOSTNAME}" \
        --accept-dns=false \
        --ssh=true \
        --accept-routes=true

    if [ $? -ne 0 ]; then
        echo "错误：tailscale up 失败"
        return
    fi

    tailscale set --relay-server-port=61241
    sleep 5
    if tailscale status 2>/dev/null | grep -q "100\."; then
        echo "✓ Tailscale 连接成功"
    else
        echo "警告：Tailscale 连接不稳定"
    fi
}

# --- 【最终正确】代理配置（Headscale + 用户模式专用）---
get_proxy_env() { 
    if [ "$TAILSCALE_ENABLED" = "true" ] && [ -n "$TAILSCALE_AUTHKEY" ]; then 
        echo "--env ALL_PROXY=socks5://172.18.0.1:1055" 
    else 
        echo "" 
    fi 
}

# --- 私有仓库自动登录 ---
login_private_registry() {
    if [ -z "${CNB_TOKEN_USER_NAME}" ] || [ -z "${CNB_TOKEN}" ]; then
        echo "错误：私有仓库登录失败。环境变量 CNB_TOKEN_USER_NAME 或 CNB_TOKEN 未设置。"
        echo "请先执行: export CNB_TOKEN_USER_NAME='你的用户名' 和 export CNB_TOKEN='你的Token'"
        exit 1
    fi

    echo "正在登录到 $PRIVATE_REGISTRY..."
    if docker login -u "${CNB_TOKEN_USER_NAME}" -p "${CNB_TOKEN}" "${PRIVATE_REGISTRY}"; then
        echo "登录成功！"
        LOGGED_IN=true
    else
        echo "错误：登录私有仓库 $PRIVATE_REGISTRY 失败，请检查凭证。"
        exit 1
    fi
}

# --- 容器启动配置 ---
start_containers() {
    local proxy_env=$(get_proxy_env)

    echo "开始启动容器..."

    # 容器1：raw
    echo "处理容器1：raw"
    docker stop raw &> /dev/null
    docker rm raw &> /dev/null
    if [ -n "$GH_TOKEN" ]; then
        docker run -d --name raw -p 30001:3000 \
            -e GH_TOKEN="$GH_TOKEN" \
            ${proxy_env} \
            docker.cnb.cool/xzydm/raw2my/raw:latest
    else
        docker run -d --name raw -p 30001:3000 \
            ${proxy_env} \
            docker.cnb.cool/xzydm/raw2my/raw:latest
        echo "警告：未设置 GH_TOKEN 环境变量，raw 容器可能无法正常工作"
    fi

    # 容器2：hubproxy
    echo "处理容器2：hubproxy"
    docker stop hubproxy &> /dev/null
    docker rm hubproxy &> /dev/null
    docker run -d --name hubproxy -p 30002:5000 --restart always \
        ${proxy_env} \
        ghcr.io/sky22333/hubproxy

    # 容器3：subapi
    echo "处理容器3：subapi"
    docker stop subapi &> /dev/null
    docker rm subapi &> /dev/null
    docker run -d --name subapi -p 30003:25500 \
        ${proxy_env} \
        asdlokj1qpi23/subconverter

    # 容器4：gh-proxy
    echo "处理容器4：gh-proxy"
    docker stop gh-proxy &> /dev/null
    docker rm gh-proxy &> /dev/null
    docker run -d --name gh-proxy -p 30004:8080 --restart always -e WK_BLOCK_HOME=1 \
        ${proxy_env} \
        docker.cnb.cool/xzydm/cf-worker-project/gh-proxy:latest

    echo "所有容器启动命令执行完成，请通过 docker ps 检查状态"
}

# --- 主流程 ---
main() {
    login_private_registry
    start_tailscale_userspace
    start_containers
}

main