#!/bin/bash
# ============================================================
# 双用途脚本：
#   - 作为 ocl-firewall-ini.sh 执行 → 初始化防火墙
#   - 作为 setfirewall 执行       → 防火墙管理菜单/命令行
#
# 初始化完成后会自动部署自身到 /usr/local/bin/setfirewall
#
# ⚠️ 重要：所有 iptables 操作均使用纯 iptables 语法（-D + -A/-I 模式）
# 不使用 iptables -C（规则检查），因为 Ubuntu 24.04 的 iptables 是
# nf_tables 兼容层，-C 会内部调用 nft 后端导致 "nft-xxx" 错误。
# 参见 easytier-firewall.sh 的写法：先 -D 删除旧规则（允许失败），
# 再 -A/-I 添加新规则，确保幂等性。
#
# ⚠️ 规则顺序原则（iptables 从上到下匹配，先匹配先生效）：
#
#   INPUT 链正确的规则顺序（从上到下）：
#   ┌─────────────────────────────────────────────────────────────┐
#   │ 1. 管理子链跳转（ts-input, 1PANEL_INPUT, et-input 等）      │ ← 第三方自动注入并置顶
#   │    这些子链自身有完善的过滤逻辑，不会误放行公网流量           │
#   │    et-input 中还包含 EasyTier 监听端口 RETURN 规则，          │
#   │    让 VPN 流量绕过 DDOS-PROTECT 限速                        │
#   │    NetBird 使用 WireGuard 接口 wt0，直接在主链添加规则        │
#   │ 2. lo ACCEPT（本地回环）                                    │ ← 保命规则
#   │ 3. conntrack ESTABLISHED,RELATED（已建连接放行）             │ ← 保命规则
#   │ 4. SSH 防断连临时放行                                       │ ← 初始化临时
#   │ 5. 元数据 169.254.0.0/16 ACCEPT                             │ ← 保命规则
#   │ 5.5. VPN/内网 ICMP 永久放行（tailscale0, easytier 等）       │ ← 保命规则
#   │      不受 p-on/p-off 控制，内网 ping 始终允许                │
#   │ 6. IPv6 icmpv6 / NDP 基础放行                               │ ← 保命规则
#   │ 7. DDOS-PROTECT 子链跳转                                    │ ← 限速防护
#   │    子链内：SYN限速→RETURN回主链 / UDP限速→RETURN回主链        │
#   │ 8. IP 黑名单 DROP（优先拦截恶意IP）                          │ ← 黑名单
#   │ 9. IP 白名单 ACCEPT（信任IP优先放行）                        │ ← 白名单
#   │ 10. 端口 ACCEPT/DROP 规则                                   │ ← 业务端口
#   │    └─ 端口 DROP 规则在对应 ACCEPT 之前（确保关闭优先）        │
#   │ 11. 默认策略 DROP                                          │ ← 兜底
#   └─────────────────────────────────────────────────────────────┘
#
#   setfirewall 操作时遵循的插入位置规则：
#   - 管理/VPN端口（pre-ddos）：插入到 DDOS-PROTECT 之前（层1位置）
#     适用于 VPN 监听端口等需要绕过限速检查的端口
#   - IP 黑名单：插入到 DDOS-PROTECT 之后（第8层位置）
#   - IP 白名单：插入到 DDOS-PROTECT 之后（第9层位置）
#   - 端口 ACCEPT：追加到链末尾（第10层位置）
#   - 端口 DROP：插入到 DDOS-PROTECT 之后（同层内DROP优先）
#   - 网卡规则：根据动作类型，ACCEPT→端口层，DROP→黑名单层
#
#   FORWARD 链正确的规则顺序：
#   1. 管理子链跳转（et-forward, ts-forward 等）
#   2. DOCKER-USER（用户自定义 Docker 过滤）
#      使用 setfirewall docker-* 命令管控 Docker 转发流量
#      （docker-block-port / docker-allow-ip / docker-block-ip 等）
#   3. Docker 自管子链（DOCKER-ISOLATION, DOCKER）
#   4. docker0 手动转发规则
#   5. 默认策略 DROP
# ============================================================

# ============================================================
# 可调常量区（集中管理，方便审查和调阅）
# 初始化模式下可通过命令参数覆盖，如：
#   ./ocl-firewall-ini.sh --ssh-port=2222 --ports="2222 80 443"
#   ./ocl-firewall-ini.sh --ddos-syn-rate=1000 --no-ddos
# 未指定参数时使用下方默认值
# ============================================================

# --- 端口常量（默认自动检测）---
# 默认值，脚本会自动检测实际值
SSH_PORT=22                     # SSH 服务端口（自动检测）
PORTS=(80 443)                  # 业务放行端口列表（80/443 固定，1Panel 等动态检测）
TAILSCALE_PORT=59358            # Tailscale 固定端口（写入配置文件）

# ============================================================
# 自动检测函数（仅在初始化模式下调用）
# ============================================================

# 自动检测 SSH 端口（从 sshd_config 读取）
auto_detect_ssh_port() {
    local config_file="/etc/ssh/sshd_config"
    if [ -f "$config_file" ]; then
        local port=$(grep -E "^Port[[:space:]]+" "$config_file" | awk '{print $2}' | head -1)
        if [ -n "$port" ] && [[ "$port" =~ ^[0-9]+$ ]]; then
            echo "$port"
            return 0
        fi
    fi
    # 兜底：尝试从 ss 命令获取 SSH 监听端口
    local ssh_port=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | grep -oE ':[0-9]+$' | tr -d ':')
    if [ -n "$ssh_port" ]; then
        echo "$ssh_port"
        return 0
    fi
    # 兜底：默认端口
    echo "22"
}

# 自动检测 1Panel 是否运行（支持 systemctl 和 1pctl 两种方式）
is_1panel_running() {
    # 方法1：systemd 服务方式（服务名为 1panel-core）
    if systemctl is-active --quiet 1panel-core 2>/dev/null; then
        return 0
    fi
    # 方法2：1pctl 管理工具方式（原生安装的1Panel）
    if command -v 1pctl &>/dev/null && 1pctl status 2>/dev/null | grep -q "Core.*正在运行"; then
        return 0
    fi
    return 1
}

# 自动检测 1Panel 监听端口
auto_detect_1panel_ports() {
    local ports=()
    # 方法1：从 1panel user-info 获取面板地址中的端口
    # 支持多种 URL 格式：
    #   http://168.107.36.225:41661/19930508  (IPv4 + 数字路径)
    #   http://example.com:41661/path         (域名 + 字母路径)
    #   http://[2001:db8::1]:41661/path       (IPv6 地址)
    #   https://domain.com:443/path            (HTTPS)
    if command -v 1panel &>/dev/null; then
        local panel_info=$(1panel user-info 2>/dev/null)
        if [ -n "$panel_info" ]; then
            # 分两种情况匹配 URL：
            # 1. IPv6 地址格式: http://[...]:port
            # 2. IPv4/域名格式: http://host:port
            local panel_port=$(echo "$panel_info" | grep -oE '(http|https)://\[[^\]]+\]:[0-9]+|(http|https)://[^:]+:[0-9]+' | grep -oE ':[0-9]+' | tr -d ':' | head -1)
            if [ -n "$panel_port" ]; then
                ports+=("$panel_port")
            fi
        fi
    fi
    # 方法2：从 nginx 配置获取（1Panel 通常使用 nginx 反向代理）
    if [ -f /etc/nginx/conf.d/1panel.conf ]; then
        local nginx_port=$(grep -oE 'proxy_pass http://[^:]+:[0-9]+' /etc/nginx/conf.d/1panel.conf 2>/dev/null | grep -oE ':[0-9]+$' | tr -d ':' | sort -u)
        if [ -n "$nginx_port" ]; then
            for p in $nginx_port; do
                if [[ ! " ${ports[@]} " =~ " ${p} " ]]; then
                    ports+=("$p")
                fi
            done
        fi
    fi
    # 方法3：检测 Docker 容器中的 1Panel 端口映射
    if systemctl is-active --quiet docker 2>/dev/null; then
        local docker_ports=$(docker ps --filter "name=1panel" --format "{{.Ports}}" 2>/dev/null | grep -oE '[0-9]+->[0-9]+/tcp' | cut -d'>' -f2 | cut -d'/' -f1 | sort -u)
        if [ -n "$docker_ports" ]; then
            for p in $docker_ports; do
                if [[ ! " ${ports[@]} " =~ " ${p} " ]]; then
                    ports+=("$p")
                fi
            done
        fi
    fi
    # 输出端口列表（空格分隔）
    echo "${ports[@]}"
}

# 自动检测已放行的非 SSH 端口
auto_detect_existing_ports() {
    local ports=()
    # 检测 iptables 中已存在的 ACCEPT 规则端口（排除 SSH）
    local existing=$(iptables -L INPUT -n --line-numbers 2>/dev/null | grep -E "ACCEPT.*dpt:" | grep -oE "dpt:[0-9]+" | cut -d: -f2 | sort -un)
    for p in $existing; do
        # 排除 SSH 端口和已有固定端口
        if [ "$p" != "$SSH_PORT" ] && [ "$p" != "80" ] && [ "$p" != "443" ]; then
            # 排除已知的服务端口（这些由对应服务管理）
            case "$p" in
                59358) continue ;;  # Tailscale
                41661) continue ;;  # EasyTier
                *) ;;
            esac
            ports+=("$p")
        fi
    done
    echo "${ports[@]}"
}

# --- 网络常量 ---
METADATA_CIDR="169.254.0.0/16" # AWS/Oracle 元数据网段（保命规则）
DEFAULT_ETH_FALLBACK="eth0"     # 默认网卡兜底值（自动检测优先）

# --- DDoS 限速常量 ---
ENABLE_DDOS_DEFENSE=false       # 是否启用 DDoS 防御（默认关闭，用户可通过 setfirewall ddos-on 手动开启）
DDOS_SYN_RATE=500               # TCP SYN 限速（包/秒）
DDOS_SYN_BURST=100              # TCP SYN 突发上限（包）
DDOS_UDP_RATE=3000              # UDP 限速（包/秒）

# --- 持久化路径 ---
RULES_V4="/etc/iptables/rules.v4"
RULES_V6="/etc/iptables/rules.v6"

# --- Tailscale 配置路径 ---
TAILSCALE_CONF="/etc/default/tailscaled"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

[ "$EUID" -ne 0 ] && { echo -e "${RED}❌ 请使用 root 用户执行此脚本${NC}"; exit 1; }

# ============================================================
# 判断运行模式：通过脚本文件名决定
# ============================================================
SCRIPT_NAME=$(basename "$0")

# ============================================================
# 初始化模式：命令行参数解析（覆盖常量）
# 仅在初始化模式下生效，setfirewall 模式忽略
# 格式：--key=value 或 --flag（布尔开关）
# ============================================================
parse_init_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --ssh-port=*)        SSH_PORT="${1#*=}" ;;
            --ports=*)           IFS=' ' read -ra PORTS <<< "${1#*=}" ;;
            --tailscale-port=*)  TAILSCALE_PORT="${1#*=}" ;;
            --metadata-cidr=*)   METADATA_CIDR="${1#*=}" ;;
            --default-eth=*)     DEFAULT_ETH_FALLBACK="${1#*=}" ;;
            --ddos-syn-rate=*)   DDOS_SYN_RATE="${1#*=}" ;;
            --ddos-syn-burst=*)  DDOS_SYN_BURST="${1#*=}" ;;
            --ddos-udp-rate=*)   DDOS_UDP_RATE="${1#*=}" ;;
            --no-ddos)           ENABLE_DDOS_DEFENSE=false ;;
            --ddos)              ENABLE_DDOS_DEFENSE=true ;;
            --rules-v4=*)        RULES_V4="${1#*=}" ;;
            --rules-v6=*)        RULES_V6="${1#*=}" ;;
            --help|-h)
                echo "用法: ./ocl-firewall-ini.sh [选项...]"
                echo ""
                echo "  初始化模式专用参数（覆盖内置常量）："
                echo ""
                echo "  端口:"
                echo "    --ssh-port=PORT          SSH 端口 (默认: ${SSH_PORT})"
                echo "    --ports=\"P1 P2 ...\"      业务端口列表 (默认: ${PORTS[*]})"
                echo "    --tailscale-port=PORT    Tailscale 固定端口 (默认: ${TAILSCALE_PORT})"
                echo ""
                echo "  网络:"
                echo "    --metadata-cidr=CIDR     元数据网段 (默认: ${METADATA_CIDR})"
                echo "    --default-eth=NIC        默认网卡兜底 (默认: ${DEFAULT_ETH_FALLBACK})"
                echo ""
                echo "  DDoS:"
                echo "    --ddos-syn-rate=N        SYN 限速包/秒 (默认: ${DDOS_SYN_RATE})"
                echo "    --ddos-syn-burst=N       SYN 突发上限 (默认: ${DDOS_SYN_BURST})"
                echo "    --ddos-udp-rate=N        UDP 限速包/秒 (默认: ${DDOS_UDP_RATE})"
                echo "    --no-ddos                禁用 DDoS 防御"
                echo "    --ddos                    强制启用 DDoS 防御（默认关闭，用 setfirewall ddos-on 开启）"
                echo ""
                echo "  持久化:"
                echo "    --rules-v4=PATH          IPv4 规则文件路径 (默认: ${RULES_V4})"
                echo "    --rules-v6=PATH          IPv6 规则文件路径 (默认: ${RULES_V6})"
                echo ""
                echo "  未指定的参数使用内置默认值"
                exit 0 ;;
            *)
                echo -e "${RED}❌ 未知参数: $1${NC}"
                echo "使用 --help 查看可用选项"
                exit 1 ;;
        esac
        shift
    done
}

# ============================================================
# 公共变量与工具函数（两种模式共用）
# ============================================================

DEFAULT_ETH=$(ip route | awk '/default/ {print $5; exit}')
[ -z "$DEFAULT_ETH" ] && DEFAULT_ETH="$DEFAULT_ETH_FALLBACK"

# ============================================================
# 双栈自适应检测
# 检测当前服务器是否实际拥有 IPv4 / IPv6 地址，
# 只对实际存在的协议栈操作 iptables / ip6tables，避免在纯 v4
# 服务器上设置 v6 规则（或反之）导致报错或无效规则。
# ============================================================

HAS_V4=false
HAS_V6=false

detect_ip_stack() {
    # 检测是否有非 lo 网卡上绑定了 IPv4 地址
    if ip -4 addr show 2>/dev/null | grep -v 'scope lo' | grep -q 'inet '; then
        HAS_V4=true
    fi
    # 检测是否有非 lo 网卡上绑定了全局 IPv6 地址（排除 fe80::/10 链路本地地址）
    if ip -6 addr show 2>/dev/null | grep -v 'scope lo' | grep -v 'scope link' | grep -q 'inet6 '; then
        HAS_V6=true
    fi
}

# 返回需要操作的防火墙命令列表（iptables 和/或 ip6tables）
get_active_cmds() {
    local cmds=()
    $HAS_V4 && cmds+=("iptables")
    $HAS_V6 && cmds+=("ip6tables")
    # 兜底：如果两个都没检测到，至少操作 iptables（不应出现此情况）
    [ ${#cmds[@]} -eq 0 ] && cmds+=("iptables")
    echo "${cmds[@]}"
}

# 判断指定命令是否应该执行（根据协议栈检测结果）
should_run_cmd() {
    local cmd="$1"
    if [ "$cmd" = "iptables" ]; then
        $HAS_V4 && return 0 || return 1
    elif [ "$cmd" = "ip6tables" ]; then
        $HAS_V6 && return 0 || return 1
    fi
    return 0
}

# ============================================================
# 规则位置感知辅助函数
# ⚠️ iptables 规则顺序至关重要！从上到下匹配，先匹配先生效。
# 这些函数确保 setfirewall 操作时规则插入到正确的位置层，
# 不会破坏保命规则（lo、conntrack）和防护规则（DDOS-PROTECT）的顺序。
#
# INPUT 链分层设计（从上到下）：
#   层1: 管理子链跳转 + VPN端口RETURN（ts-input, et-input 等，由第三方服务自动注入并置顶）
#        VPN监听端口在此层使用 RETURN，绕过 DDOS-PROTECT 限速
#        NetBird 使用 WireGuard 接口 wt0，直接在主链添加规则（非子链模式）
#   层2: 保命规则 (lo, conntrack, $METADATA_CIDR, VPN/内网ICMP, IPv6基础)
#        VPN/内网 ICMP 永久放行（tailscale0, easytier, wt0 等），不受 p-on/p-off 控制
#   层3: DDOS-PROTECT 子链跳转
#   层4: IP 黑名单 DROP 规则
#   层5: IP 白名单 ACCEPT 规则
#   层6: 端口规则 (ACCEPT/DROP)
#   层末: 默认策略 DROP
#
# 每层内的规则顺序由具体函数控制（如端口DROP在对应ACCEPT之前）
# ============================================================

# 计算 DDOS-PROTECT 子链跳转在 INPUT 链中的行号
# 返回 DDOS-PROTECT 之前的位置（用于管理/VPN端口等需要绕过限速的规则）
get_pre_ddos_pos() {
    local cmd="${1:-iptables}"
    local chain="${2:-INPUT}"
    local pos=$($cmd -L "$chain" -n --line-numbers 2>/dev/null | awk '/DDOS-PROTECT/{print $1; exit}')
    if [ -n "$pos" ] && [ "$pos" -gt 0 ] 2>/dev/null; then
        echo "$pos"
    else
        # 没有 DDOS-PROTECT 子链时，找 conntrack 行号，插入到其之后
        local ct_pos=$($cmd -L "$chain" -n --line-numbers 2>/dev/null | awk '/conntrack.*ESTABLISHED/{print $1; exit}')
        if [ -n "$ct_pos" ] && [ "$ct_pos" -gt 0 ] 2>/dev/null; then
            echo "$((ct_pos + 1))"
        else
            # 兜底：找不到 conntrack 时插入到第1行（不应出现此情况）
            echo 1
        fi
    fi
}

# 计算 DDOS-PROTECT 子链跳转在 INPUT 链中的行号（层3边界）
# 返回 DDOS-PROTECT 之后的位置（用于IP规则、端口规则等正常业务规则）
get_ddos_pos() {
    local cmd="${1:-iptables}"
    local chain="${2:-INPUT}"
    local pos=$($cmd -L "$chain" -n --line-numbers 2>/dev/null | awk '/DDOS-PROTECT/{print $1; exit}')
    if [ -n "$pos" ] && [ "$pos" -gt 0 ] 2>/dev/null; then
        echo "$((pos + 1))"
    else
        # 没有 DDOS-PROTECT 子链时，找 conntrack 行号，插入到其之后
        local ct_pos=$($cmd -L "$chain" -n --line-numbers 2>/dev/null | awk '/conntrack.*ESTABLISHED/{print $1; exit}')
        if [ -n "$ct_pos" ] && [ "$ct_pos" -gt 0 ] 2>/dev/null; then
            echo "$((ct_pos + 1))"
        else
            # 兜底：找不到 conntrack 时插入到第1行（不应出现此情况）
            echo 1
        fi
    fi
}

# 计算端口 ACCEPT 规则的插入位置（层6）
# 端口规则应插入到 IP 白名单之后，或在 DDOS-PROTECT 之后（如果没有IP规则）
# 使用 -A 追加到链末尾即可（在默认策略之前）
get_port_accept_pos() {
    # 端口 ACCEPT 规则使用 -A 追加（在默认策略DROP之前）
    # 因为端口规则层位于 IP 规则层之后，追加自然在正确位置
    echo "append"
}

# 计算端口 DROP 规则的插入位置
# 端口 DROP 需要在同端口的 ACCEPT 之前，使用 -D + 重新 -I 方式确保
get_port_drop_pos() {
    # 端口 DROP 规则：先删除同端口的 ACCEPT，然后 -I 到 DDOS-PROTECT 之后
    # 这样 DROP 在 ACCEPT 前面，确保关闭优先
    local cmd="${1:-iptables}"
    local chain="${2:-INPUT}"
    get_ddos_pos "$cmd" "$chain"
}

# 计算 IP 黑名单 DROP 规则的插入位置（层4）
# 黑名单应在 DDOS-PROTECT 之后，白名单之前
get_ip_block_pos() {
    local cmd="${1:-iptables}"
    local chain="${2:-INPUT}"
    get_ddos_pos "$cmd" "$chain"
}

# 计算 IP 白名单 ACCEPT 规则的插入位置（层5）
# 白名单应在黑名单之后
get_ip_allow_pos() {
    local cmd="${1:-iptables}"
    local chain="${2:-INPUT}"
    # 先找黑名单规则的位置，白名单应在其后
    # 如果没有黑名单规则，就插入到 DDOS-PROTECT 之后
    local ddos_pos=$(get_ddos_pos "$cmd" "$chain")
    # 查找最后一个 IP DROP 规则（黑名单）的位置
    # 修复: iptables 输出格式中不包含 "src" 字符串,改为匹配 DROP 规则
    # 并排除通配地址(0.0.0.0/0 和 ::/0),只匹配具体 IP 的 DROP 规则
    local last_block=$($cmd -L "$chain" -n --line-numbers 2>/dev/null | awk '/DROP/ && $5 !~ /^(0\.0\.0\.0\/0|::\/0|\*)$/ {print $1}' | tail -1)
    if [ -n "$last_block" ]; then
        echo "$((last_block + 1))"
    else
        echo "$ddos_pos"
    fi
}

save_rules() {
    mkdir -p /etc/iptables
    if $HAS_V4; then
        iptables-save > "$RULES_V4"
    fi
    if $HAS_V6; then
        ip6tables-save > "$RULES_V6"
    fi
}

# 判断端口参数是否为范围格式（如 80:100）
# 注意：IPv6 地址也包含冒号，需要排除（如 ::1, fe80::1）
is_port_range() {
    local port="$1"
    # 排除 IPv6 地址（包含字母或纯十六进制:的情况）
    # 端口范围必须是 数字:数字 格式
    if [[ "$port" =~ ^[0-9]+:[0-9]+$ ]]; then
        return 0
    fi
    return 1
}

validate_port() {
    local port="$1"
    # 支持范围端口格式 start:end（如 80:100）
    if is_port_range "$port"; then
        local start end
        start="${port%%:*}"
        end="${port##*:}"
        # 验证起始和结束端口都是有效数字
        if ! [[ "$start" =~ ^[0-9]+$ ]] || ! [[ "$end" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}   ⚠️  端口范围 $port 无效（格式应为 start:end，如 80:100），已跳过${NC}"
            return 1
        fi
        if [ "$start" -lt 1 ] || [ "$start" -gt 65535 ] || [ "$end" -lt 1 ] || [ "$end" -gt 65535 ]; then
            echo -e "${RED}   ⚠️  端口范围 $port 无效（1-65535），已跳过${NC}"
            return 1
        fi
        if [ "$start" -gt "$end" ]; then
            echo -e "${RED}   ⚠️  端口范围 $port 无效（起始端口不能大于结束端口），已跳过${NC}"
            return 1
        fi
        return 0
    fi
    # 单端口验证
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && return 0
    echo -e "${RED}   ⚠️  端口 $port 无效（1-65535），已跳过${NC}"
    return 1
}

# 构建 iptables 端口参数（单端口用 --dport，范围端口用 -m multiport --dports）
build_port_args() {
    local port="$1"
    if is_port_range "$port"; then
        echo "-m multiport --dports ${port}"
    else
        echo "--dport ${port}"
    fi
}

# 验证 IP 地址/网段格式
validate_ip() {
    local ip="$1"
    # IPv6: 改进验证,检查基本格式而非仅冒号
    if [[ "$ip" == *:* ]]; then
        # IPv6 基本格式验证: 必须包含至少一个冒号,且符合基本格式
        # 允许: ::1, fe80::/10, 2001:db8::/32, ::/0 等
        if [[ "$ip" =~ ^[0-9a-fA-F:]+(/[0-9]+)?$ ]] || [[ "$ip" =~ ^::(/[0-9]+)?$ ]]; then
            return 0  # IPv6 格式由 ip6tables 本身二次验证
        fi
        echo -e "${RED}   ⚠️  IPv6 格式 $ip 无效，已跳过${NC}"
        return 1
    fi
    
    # IPv4: 改进验证,检查八位组范围(0-255)
    # 格式: A.B.C.D 或 A.B.C.D/MASK 或 0/0
    if [[ "$ip" =~ ^[0-9]+/[0-9]+$ ]]; then
        # 特殊格式 0/0 (通配地址)
        return 0
    fi
    
    # 标准 IPv4 格式: A.B.C.D 或 A.B.C.D/MASK
    if [[ "$ip" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)(/[0-9]+)?$ ]]; then
        local octet1="${BASH_REMATCH[1]}"
        local octet2="${BASH_REMATCH[2]}"
        local octet3="${BASH_REMATCH[3]}"
        local octet4="${BASH_REMATCH[4]}"
        local mask="${BASH_REMATCH[5]}"
        
        # 验证每个八位组范围(0-255)
        for octet in "$octet1" "$octet2" "$octet3" "$octet4"; do
            if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
                echo -e "${RED}   ⚠️  IPv4 八位组 $octet 超出范围(0-255)，已跳过${NC}"
                return 1
            fi
        done
        
        # 验证掩码范围(0-32)
        if [ -n "$mask" ]; then
            mask="${mask#/}"  # 移除斜杠
            if [ "$mask" -lt 0 ] || [ "$mask" -gt 32 ]; then
                echo -e "${RED}   ⚠️  IPv4 掩码 $mask 超出范围(0-32)，已跳过${NC}"
                return 1
            fi
        fi
        
        return 0
    fi
    
    echo -e "${RED}   ⚠️  IP 格式 $ip 无效，已跳过${NC}"
    return 1
}

# 验证 iptables 动作参数
validate_action() {
    local action="$1"
    [[ "$action" == "ACCEPT" || "$action" == "DROP" || "$action" == "REJECT" || "$action" == "RETURN" ]] && return 0
    echo -e "${RED}   ⚠️  动作 $action 无效（ACCEPT/DROP/REJECT/RETURN），已跳过${NC}"
    return 1
}

# 验证协议参数
validate_proto() {
    local proto="$1"
    [[ "$proto" == "tcp" || "$proto" == "udp" || "$proto" == "all" ]] && return 0
    echo -e "${RED}   ⚠️  协议 $proto 无效（tcp/udp/all），已跳过${NC}"
    return 1
}

list_nics() {
    echo -e "${BLUE}可用网卡列表:${NC}"
    for nic in $(ls /sys/class/net); do
        local state=$(cat /sys/class/net/$nic/operstate 2>/dev/null)
        local ipaddr=$(ip -4 addr show $nic 2>/dev/null | awk '/inet /{print $2}' | head -n1)
        local ip6addr=$(ip -6 addr show $nic 2>/dev/null | awk '/inet6/{print $2}' | head -n1)
        printf "  %-14s 状态: %-8s  IPv4: %-18s IPv6: %s\n" "$nic" "${state:-unknown}" "${ipaddr:-无}" "${ip6addr:-无}"
    done
}

# ============================================================
# 管理功能函数
# ⚠️ 全部使用 -D + -A/-I 模式（参考 easytier-firewall.sh）
# 不使用 iptables -C，避免 nf_tables 后端 "nft-xxx" 错误
# ============================================================

open_port() {
    local ports=($@)
    [ ${#ports[@]} -eq 0 ] && { echo -e "${RED}请提供至少一个端口号或端口范围（如 80:100）${NC}"; return 1; }
    for port in "${ports[@]}"; do
        validate_port "$port" || continue
        local port_args=$(build_port_args "$port")
        local port_label=$port
        is_port_range "$port" && port_label="范围 ${port}"
        # 先删除可能存在的旧规则（DROP 和 ACCEPT 都删），确保幂等
        for cmd in $(get_active_cmds); do
            for proto in tcp udp; do
                $cmd -D INPUT -p "$proto" $port_args -j DROP 2>/dev/null || true
                $cmd -D INPUT -p "$proto" $port_args -j ACCEPT 2>/dev/null || true
                # 端口 ACCEPT 规则追加到链末尾（在默认策略 DROP 之前）
                # 这确保端口规则在保命规则、DDOS-PROTECT、IP黑白名单之后
                $cmd -A INPUT -p "$proto" $port_args -j ACCEPT
                local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
                echo -e "${GREEN}   ✅ ${label} ${proto^^} ${port_label} 已开放${NC}"
            done
        done
    done
    save_rules
}

# 开放端口（放置在 DDOS-PROTECT 之前）
# 适用于 VPN/管理端口等需要绕过限速检查的端口
# 规则插入到 DDOS-PROTECT 之前的位置，确保这些端口流量不被限速拦截
open_port_pre_ddos() {
    local ports=($@)
    [ ${#ports[@]} -eq 0 ] && { echo -e "${RED}请提供至少一个端口号或端口范围（如 80:100）${NC}"; return 1; }
    for port in "${ports[@]}"; do
        validate_port "$port" || continue
        local port_args=$(build_port_args "$port")
        local port_label=$port
        is_port_range "$port" && port_label="范围 ${port}"
        # 先删除可能存在的旧规则（各种位置都删），确保幂等
        for cmd in $(get_active_cmds); do
            for proto in tcp udp; do
                $cmd -D INPUT -p "$proto" $port_args -j DROP 2>/dev/null || true
                $cmd -D INPUT -p "$proto" $port_args -j ACCEPT 2>/dev/null || true
                # 插入到 DDOS-PROTECT 之前（绕过限速）
                local pos=$(get_pre_ddos_pos "$cmd" INPUT)
                $cmd -I INPUT $pos -p "$proto" $port_args -j ACCEPT
                local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
                echo -e "${GREEN}   ✅ ${label} ${proto^^} ${port_label} 已开放（绕过DDoS限速）${NC}"
            done
        done
    done
    save_rules
}

close_port() {
    local ports=($@)
    [ ${#ports[@]} -eq 0 ] && { echo -e "${RED}请提供至少一个端口号或端口范围（如 80:100）${NC}"; return 1; }
    for port in "${ports[@]}"; do
        validate_port "$port" || continue
        local port_args=$(build_port_args "$port")
        local port_label=$port
        is_port_range "$port" && port_label="范围 ${port}"
        # 先删除可能存在的旧规则（ACCEPT 和 DROP 都删），确保幂等
        for cmd in $(get_active_cmds); do
            for proto in tcp udp; do
                $cmd -D INPUT -p "$proto" $port_args -j ACCEPT 2>/dev/null || true
                $cmd -D INPUT -p "$proto" $port_args -j DROP 2>/dev/null || true
                # 端口 DROP 规则插入到 DDOS-PROTECT 之后的位置（层4开始处）
                # 这样 DROP 在所有同端口 ACCEPT 之前，确保"关闭优先于开放"
                # 但仍在保命规则和 DDOS-PROTECT 之后，不会破坏安全基础
                local pos=$(get_ddos_pos "$cmd" INPUT)
                $cmd -I INPUT $pos -p "$proto" $port_args -j DROP
                local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
                echo -e "${RED}   🔒 ${label} ${proto^^} ${port_label} 已关闭${NC}"
            done
        done
    done
    save_rules
}

# 关闭端口（放置在 DDOS-PROTECT 之前）
# 适用于关闭之前用 pre-ddos 开放的 VPN/管理端口
# DROP 规则插入到 DDOS-PROTECT 之前，确保在原 ACCEPT 规则之前匹配
close_port_pre_ddos() {
    local ports=($@)
    [ ${#ports[@]} -eq 0 ] && { echo -e "${RED}请提供至少一个端口号或端口范围（如 80:100）${NC}"; return 1; }
    for port in "${ports[@]}"; do
        validate_port "$port" || continue
        local port_args=$(build_port_args "$port")
        local port_label=$port
        is_port_range "$port" && port_label="范围 ${port}"
        for cmd in $(get_active_cmds); do
            for proto in tcp udp; do
                # 先删除可能存在的旧规则（各种位置都删），确保幂等
                $cmd -D INPUT -p "$proto" $port_args -j ACCEPT 2>/dev/null || true
                $cmd -D INPUT -p "$proto" $port_args -j DROP 2>/dev/null || true
                # DROP 插入到 DDOS-PROTECT 之前（在原 pre-ddos ACCEPT 之前）
                local pos=$(get_pre_ddos_pos "$cmd" INPUT)
                $cmd -I INPUT $pos -p "$proto" $port_args -j DROP
                local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
                echo -e "${RED}   🔒 ${label} ${proto^^} ${port_label} 已关闭（DDoS限速前层）${NC}"
            done
        done
    done
    save_rules
}

allow_ip() {
    local ips=($@)
    [ ${#ips[@]} -eq 0 ] && { echo -e "${RED}请提供至少一个IP或IP段${NC}"; return 1; }
    for ip in "${ips[@]}"; do
        validate_ip "$ip" || continue
        local cmd="iptables"; [[ "$ip" == *:* ]] && cmd="ip6tables"
        # 如果目标协议栈不存在则跳过
        if ! should_run_cmd "$cmd"; then
            echo -e "${YELLOW}   ⚠️  跳过 $ip：对应的 IP 协议栈在本机不存在${NC}"
            continue
        fi
        # 先删除可能存在的旧规则（DROP 和 ACCEPT 都删），确保幂等
        $cmd -D INPUT -s "$ip" -j DROP 2>/dev/null || true
        $cmd -D INPUT -s "$ip" -j ACCEPT 2>/dev/null || true
        # IP 白名单 ACCEPT：插入到 DDOS-PROTECT 之后（层5）
        # 白名单在黑名单之后、端口规则之前
        local pos=$(get_ddos_pos "$cmd" INPUT)
        $cmd -I INPUT $pos -s "$ip" -j ACCEPT
        echo -e "${GREEN}   ✅ 已放行 IP: $ip${NC}"
    done
    save_rules
}

block_ip() {
    local ips=($@)
    [ ${#ips[@]} -eq 0 ] && { echo -e "${RED}请提供至少一个IP或IP段${NC}"; return 1; }
    for ip in "${ips[@]}"; do
        validate_ip "$ip" || continue
        local cmd="iptables"; [[ "$ip" == *:* ]] && cmd="ip6tables"
        # 如果目标协议栈不存在则跳过
        if ! should_run_cmd "$cmd"; then
            echo -e "${YELLOW}   ⚠️  跳过 $ip：对应的 IP 协议栈在本机不存在${NC}"
            continue
        fi
        # 先删除可能存在的旧规则（ACCEPT 和 DROP 都删），确保幂等
        $cmd -D INPUT -s "$ip" -j ACCEPT 2>/dev/null || true
        $cmd -D INPUT -s "$ip" -j DROP 2>/dev/null || true
        # IP 黑名单 DROP：插入到 DDOS-PROTECT 之后（层4）
        # 黑名单在 DDOS-PROTECT 之后、白名单之前
        local pos=$(get_ddos_pos "$cmd" INPUT)
        $cmd -I INPUT $pos -s "$ip" -j DROP
        echo -e "${RED}   🔒 已封锁 IP: $ip${NC}"
    done
    save_rules
}

clear_ip() {
    local ips=($@)
    [ ${#ips[@]} -eq 0 ] && { echo -e "${RED}请提供至少一个IP${NC}"; return 1; }
    for ip in "${ips[@]}"; do
        validate_ip "$ip" || continue
        local cmd="iptables"; [[ "$ip" == *:* ]] && cmd="ip6tables"
        # 如果目标协议栈不存在则跳过
        if ! should_run_cmd "$cmd"; then
            echo -e "${YELLOW}   ⚠️  跳过 $ip：对应的 IP 协议栈在本机不存在${NC}"
            continue
        fi
        $cmd -D INPUT -s "$ip" -j ACCEPT 2>/dev/null || true
        $cmd -D INPUT -s "$ip" -j DROP 2>/dev/null || true
        echo -e "${YELLOW}   🧹 已清除 IP $ip 的所有规则${NC}"
    done
    save_rules
}

nic_rule_add() {
    local chain="${1:-INPUT}"
    local nic="$2"
    local direction="${3:-i}"
    local src_ip="$4"
    local port="$5"
    local proto="${6:-tcp}"
    local action="${7:-ACCEPT}"

    [ -z "$nic" ] && { echo -e "${RED}请提供网卡名${NC}"; return 1; }
    [ -z "$src_ip" ] && { echo -e "${RED}请提供源IP或网段${NC}"; return 1; }
    validate_ip "$src_ip" || return 1
    validate_action "$action" || return 1

    if ! ip link show "$nic" &>/dev/null; then
        echo -e "${YELLOW}   ⚠️  网卡 $nic 当前不存在，仍添加规则（网卡可能稍后创建）${NC}"
    fi

    local if_flag=""
    [ "$direction" = "i" ] && if_flag="-i $nic"
    [ "$direction" = "o" ] && if_flag="-o $nic"

    local port_flag=""
    local proto_flag=""
    if [ -n "$port" ]; then
        validate_port "$port" || return 1
        port_flag=$(build_port_args "$port")
        [ "$proto" = "all" ] && proto_flag="" || { validate_proto "$proto" || return 1; proto_flag="-p $proto"; }
    fi

    # 根据源 IP 自动判断使用 iptables 或 ip6tables
    # 同时根据协议栈检测结果过滤，避免在不存在的协议栈上操作
    local cmds=()
    if [[ "$src_ip" == *:* ]]; then
        # IPv6 地址
        $HAS_V6 && cmds+=("ip6tables")
    elif [[ "$src_ip" == "0/0" || "$src_ip" == "0.0.0.0/0" ]]; then
        # IPv4 通配地址 → 双栈都添加（如果对应栈存在）
        $HAS_V4 && cmds+=("iptables")
        $HAS_V6 && cmds+=("ip6tables")
    elif [[ "$src_ip" == "::/0" ]]; then
        # IPv6 通配地址
        $HAS_V6 && cmds+=("ip6tables")
    else
        # IPv4 地址
        $HAS_V4 && cmds+=("iptables")
    fi

    if [ ${#cmds[@]} -eq 0 ]; then
        echo -e "${YELLOW}   ⚠️  跳过：目标 IP 协议栈在本机不存在${NC}"
        return 0
    fi

    for cmd in "${cmds[@]}"; do
        # 先删除可能存在的同规格旧规则（参考 easytier-firewall.sh 的 -D 先删再 -I 模式）
        $cmd -D "$chain" $if_flag -s "$src_ip" $proto_flag $port_flag -j "$action" 2>/dev/null || true
        # 根据动作类型决定插入位置，遵循分层规则顺序：
        #   DROP/REJECT → 插入到 DDOS-PROTECT 之后（黑名单层）
        #   ACCEPT      → 插入到 DDOS-PROTECT 之后（白名单/端口层）
        #   RETURN      → 使用指定位置或追加
        local pos
        if [ "$chain" = "INPUT" ]; then
            if [ "$action" = "DROP" ] || [ "$action" = "REJECT" ]; then
                pos=$(get_ddos_pos "$cmd" "$chain")
            elif [ "$action" = "ACCEPT" ]; then
                # 有端口的 ACCEPT → 追加到末尾（端口层）
                # 无端口的 ACCEPT → DDOS-PROTECT 之后（白名单层）
                if [ -n "$port" ]; then
                    pos="append"
                else
                    pos=$(get_ddos_pos "$cmd" "$chain")
                fi
            else
                pos=${INSERT_POS:-1}
            fi
        else
            # FORWARD 等其他链：使用指定位置或链最前
            pos=${INSERT_POS:-1}
        fi
        if [ "$pos" = "append" ]; then
            $cmd -A "$chain" $if_flag -s "$src_ip" $proto_flag $port_flag -j "$action"
        else
            $cmd -I "$chain" $pos $if_flag -s "$src_ip" $proto_flag $port_flag -j "$action"
        fi
        local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
        echo -e "${GREEN}   ✅ ${label} 已添加: 链:${chain} ${if_flag} -s ${src_ip} ${proto_flag} ${port_flag} -j ${action}${NC}"
    done
    save_rules
}

nic_rule_del() {
    local chain="${1:-INPUT}"
    local nic="$2"
    local direction="${3:-i}"
    local src_ip="$4"
    local port="$5"
    local proto="${6:-tcp}"
    local action="${7:-ACCEPT}"

    [ -z "$nic" ] && { echo -e "${RED}请提供网卡名${NC}"; return 1; }
    [ -z "$src_ip" ] && { echo -e "${RED}请提供源IP或网段${NC}"; return 1; }
    validate_ip "$src_ip" || return 1
    validate_action "$action" || return 1

    local if_flag=""
    [ "$direction" = "i" ] && if_flag="-i $nic"
    [ "$direction" = "o" ] && if_flag="-o $nic"

    local port_flag=""
    local proto_flag=""
    if [ -n "$port" ]; then
        validate_port "$port" || return 1
        port_flag=$(build_port_args "$port")
        [ "$proto" = "all" ] && proto_flag="" || { validate_proto "$proto" || return 1; proto_flag="-p $proto"; }
    fi

    # 根据源 IP 自动判断使用 iptables 或 ip6tables
    # 同时根据协议栈检测结果过滤，避免在不存在的协议栈上操作
    local cmds=()
    if [[ "$src_ip" == *:* ]]; then
        # IPv6 地址
        $HAS_V6 && cmds+=("ip6tables")
    elif [[ "$src_ip" == "0/0" || "$src_ip" == "0.0.0.0/0" ]]; then
        # IPv4 通配地址 → 双栈都尝试删除（如果对应栈存在）
        $HAS_V4 && cmds+=("iptables")
        $HAS_V6 && cmds+=("ip6tables")
    elif [[ "$src_ip" == "::/0" ]]; then
        # IPv6 通配地址
        $HAS_V6 && cmds+=("ip6tables")
    else
        # IPv4 地址
        $HAS_V4 && cmds+=("iptables")
    fi

    # 删除时如果没有匹配的栈，不需要报错（可能规则本就不存在）
    if [ ${#cmds[@]} -eq 0 ]; then
        echo -e "${RED}   ⚠️  规则不存在（目标 IP 协议栈在本机不存在）${NC}"
        return 0
    fi

    local deleted=false
    for cmd in "${cmds[@]}"; do
        if $cmd -D "$chain" $if_flag -s "$src_ip" $proto_flag $port_flag -j "$action" 2>/dev/null; then
            local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
            echo -e "${YELLOW}   🧹 ${label} 已删除: 链:${chain} ${if_flag} -s ${src_ip} ${proto_flag} ${port_flag} -j ${action}${NC}"
            deleted=true
        fi
    done
    if $deleted; then
        save_rules
    else
        echo -e "${RED}   ⚠️  规则不存在${NC}"
    fi
}

nic_allow_port() {
    local nic="$1"; local port="$2"; local proto="${3:-both}"
    [ -z "$nic" ] || [ -z "$port" ] && { echo -e "${RED}用法: nic_allow_port <网卡> <端口/端口范围> [tcp|udp|both]${NC}"; return 1; }
    validate_port "$port" || return 1
    local port_args=$(build_port_args "$port")
    local port_label=$port
    is_port_range "$port" && port_label="范围 ${port}"
    local protocols=(); case "$proto" in tcp) protocols=(tcp);; udp) protocols=(udp);; both) protocols=(tcp udp);; *) echo -e "${RED}协议无效${NC}"; return 1;; esac
    for cmd in $(get_active_cmds); do
        for p in "${protocols[@]}"; do
            # 先删除可能存在的旧规则（DROP 和 ACCEPT 都删），确保幂等
            $cmd -D INPUT -i "$nic" -p "$p" $port_args -j DROP 2>/dev/null || true
            $cmd -D INPUT -i "$nic" -p "$p" $port_args -j ACCEPT 2>/dev/null || true
            # 网卡端口 ACCEPT：追加到链末尾（端口层，在默认策略之前）
            $cmd -A INPUT -i "$nic" -p "$p" $port_args -j ACCEPT
            local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
            echo -e "${GREEN}   ✅ ${label} 网卡 $nic ${p^^} ${port_label} 已放行${NC}"
        done
    done
    save_rules
}

nic_block_port() {
    local nic="$1"; local port="$2"; local proto="${3:-both}"
    [ -z "$nic" ] || [ -z "$port" ] && { echo -e "${RED}用法: nic_block_port <网卡> <端口/端口范围> [tcp|udp|both]${NC}"; return 1; }
    validate_port "$port" || return 1
    local port_args=$(build_port_args "$port")
    local port_label=$port
    is_port_range "$port" && port_label="范围 ${port}"
    local protocols=(); case "$proto" in tcp) protocols=(tcp);; udp) protocols=(udp);; both) protocols=(tcp udp);; *) echo -e "${RED}协议无效${NC}"; return 1;; esac
    for cmd in $(get_active_cmds); do
        for p in "${protocols[@]}"; do
            # 先删除可能存在的旧规则（ACCEPT 和 DROP 都删），确保幂等
            $cmd -D INPUT -i "$nic" -p "$p" $port_args -j ACCEPT 2>/dev/null || true
            $cmd -D INPUT -i "$nic" -p "$p" $port_args -j DROP 2>/dev/null || true
            # 网卡端口 DROP：插入到 DDOS-PROTECT 之后（黑名单层开始处）
            # 确保 DROP 在同端口 ACCEPT 之前，但仍在保命规则之后
            local pos=$(get_ddos_pos "$cmd" INPUT)
            $cmd -I INPUT $pos -i "$nic" -p "$p" $port_args -j DROP
            local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
            echo -e "${RED}   🔒 ${label} 网卡 $nic ${p^^} ${port_label} 已拒绝${NC}"
        done
    done
    save_rules
}

enable_ddos() {
    # ⚠️ 关键设计：DDoS 限速规则必须放在子链中！
    # 原因：在主链（如 INPUT）中，RETURN 等同于执行默认策略（DROP），
    # 不会继续匹配后续端口 ACCEPT 规则。放在子链中，RETURN 会返回主链继续匹配。
    # 参考 easytier-firewall.sh 的子链设计模式。
    #
    # ⚠️ DDOS-PROTECT 插入位置：保命规则之后、业务端口之前
    # 管理子链跳转（et-input, ts-input 等）在 DDOS-PROTECT 之前，
    # VPN/管理端口流量可以绕过限速检查。

    # 先删除旧版直接写在主链中的 DDoS 规则（兼容历史配置）
    # 清理时两个栈都尝试（以防历史规则残留），忽略错误
    for cmd in iptables ip6tables; do
        # 删除旧版主链直写规则
        $cmd -D INPUT -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j ACCEPT 2>/dev/null || true
        $cmd -D INPUT -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j RETURN 2>/dev/null || true
        $cmd -D INPUT -p tcp --syn -j DROP 2>/dev/null || true
        $cmd -D INPUT -p udp -m limit --limit ${DDOS_UDP_RATE}/s -j RETURN 2>/dev/null || true
        $cmd -D INPUT -p udp -j DROP 2>/dev/null || true
        # 删除旧的子链跳转引用
        $cmd -D INPUT -j DDOS-PROTECT 2>/dev/null || true
    done
    # 清理 DOCKER-USER 链旧版规则（两栈都尝试，安全清理）
    for cmd in iptables ip6tables; do
        $cmd -D DOCKER-USER -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j ACCEPT 2>/dev/null || true
        $cmd -D DOCKER-USER -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j RETURN 2>/dev/null || true
        $cmd -D DOCKER-USER -p tcp --syn -j DROP 2>/dev/null || true
        $cmd -D DOCKER-USER -p udp -m limit --limit ${DDOS_UDP_RATE}/s -j RETURN 2>/dev/null || true
        $cmd -D DOCKER-USER -p udp -j DROP 2>/dev/null || true
    done

    # 创建 DDoS 防御子链（仅对实际存在的协议栈操作）
    for cmd in $(get_active_cmds); do
        # 检查子链是否已存在
        if $cmd -L DDOS-PROTECT -n &>/dev/null; then
            # 检查是否有非标准规则(超过4条标准规则: SYN限速+DROP + UDP限速+DROP)
            local rule_count=$($cmd -L DDOS-PROTECT -n 2>/dev/null | grep -v "^Chain\|^target" | grep -c "^")
            if [ "$rule_count" -gt 4 ]; then
                echo -e "${YELLOW}   ⚠️  DDOS-PROTECT 子链已存在且有自定义规则(${rule_count}条),将被清空并重建${NC}"
            fi
            $cmd -F DDOS-PROTECT
        else
            $cmd -N DDOS-PROTECT 2>/dev/null || true
        fi

        # TCP SYN 限速：
        # 超限 → DROP（防洪水攻击）
        # 未超限 → RETURN（返回主链继续匹配端口 ACCEPT 规则）
        # ⚠️ 在子链中 RETURN 才会返回主链，在主链中 RETURN 等于执行默认策略 DROP！
        $cmd -A DDOS-PROTECT -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j RETURN
        $cmd -A DDOS-PROTECT -p tcp --syn -j DROP

        # UDP 限速：
        # 超限 → DROP（防洪水攻击）
        # 未超限 → RETURN（返回主链继续匹配端口规则）
        $cmd -A DDOS-PROTECT -p udp -m limit --limit ${DDOS_UDP_RATE}/s -j RETURN
        $cmd -A DDOS-PROTECT -p udp -j DROP

        # 将子链插入到 INPUT 链中保命规则之后的位置
        # ⚠️ 位置感知：DDOS-PROTECT 应在保命规则之后、业务端口之前
        # 管理子链跳转（et-input 等）在 DDOS-PROTECT 之前不受影响
        local insert_pos=1
        # 优先找 conntrack 行号，插入到其之后
        local ct_line=$($cmd -L INPUT -n --line-numbers 2>/dev/null | awk '/conntrack.*ESTABLISHED/{print $1; exit}')
        if [ -n "$ct_line" ]; then
            insert_pos=$((ct_line + 1))
        else
            # 兜底：找 lo 行号
            local lo_line=$($cmd -L INPUT -n --line-numbers 2>/dev/null | awk '/lo.*ACCEPT/{print $1; exit}')
            if [ -n "$lo_line" ]; then
                insert_pos=$((lo_line + 1))
            else
                insert_pos=1
            fi
        fi
        $cmd -I INPUT $insert_pos -j DDOS-PROTECT
    done

    # DOCKER-USER 链 DDoS 防御（也是子链，RETURN 会返回 DOCKER-USER 继续匹配）
    # 仅对实际存在的协议栈操作
    for cmd in $(get_active_cmds); do
        $cmd -D DOCKER-USER -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j ACCEPT 2>/dev/null || true
        $cmd -D DOCKER-USER -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j RETURN 2>/dev/null || true
        $cmd -D DOCKER-USER -p tcp --syn -j DROP 2>/dev/null || true
        $cmd -D DOCKER-USER -p udp -m limit --limit ${DDOS_UDP_RATE}/s -j RETURN 2>/dev/null || true
        $cmd -D DOCKER-USER -p udp -j DROP 2>/dev/null || true
        $cmd -A DOCKER-USER -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j RETURN
        $cmd -A DOCKER-USER -p tcp --syn -j DROP
        $cmd -A DOCKER-USER -p udp -m limit --limit ${DDOS_UDP_RATE}/s -j RETURN
        $cmd -A DOCKER-USER -p udp -j DROP
    done

    echo -e "${GREEN}   🛡️  DDoS 防御已启用（子链 DDOS-PROTECT，RETURN 正确返回主链）${NC}"
    save_rules
}

disable_ddos() {
    # 清理时两个栈都尝试（安全清理历史规则），忽略错误
    for cmd in iptables ip6tables; do
        # 删除旧版主链直写规则（兼容历史配置）
        $cmd -D INPUT -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j ACCEPT 2>/dev/null || true
        $cmd -D INPUT -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j RETURN 2>/dev/null || true
        $cmd -D INPUT -p tcp --syn -j DROP 2>/dev/null || true
        $cmd -D INPUT -p udp -m limit --limit ${DDOS_UDP_RATE}/s -j RETURN 2>/dev/null || true
        $cmd -D INPUT -p udp -j DROP 2>/dev/null || true
        # 删除子链跳转引用并清空子链
        $cmd -D INPUT -j DDOS-PROTECT 2>/dev/null || true
        $cmd -F DDOS-PROTECT 2>/dev/null || true
        $cmd -X DDOS-PROTECT 2>/dev/null || true
    done
    # DOCKER-USER 链 DDoS 规则清理（两栈都尝试，安全清理）
    for cmd in iptables ip6tables; do
        $cmd -D DOCKER-USER -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j ACCEPT 2>/dev/null || true
        $cmd -D DOCKER-USER -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j RETURN 2>/dev/null || true
        $cmd -D DOCKER-USER -p tcp --syn -j DROP 2>/dev/null || true
        $cmd -D DOCKER-USER -p udp -m limit --limit ${DDOS_UDP_RATE}/s -j RETURN 2>/dev/null || true
        $cmd -D DOCKER-USER -p udp -j DROP 2>/dev/null || true
    done
    echo -e "${YELLOW}   ⚠️  DDoS 防御已关闭${NC}"
    save_rules
}

enable_ping() {
    # ⚠️ 此功能仅管控公网接口的 PING！
    # VPN/内网 ping（tailscale0, easytier 等）由保命规则永久放行，不受 p-on/p-off 控制。
    # 先删除旧规则，再重新添加（参考 easytier-firewall.sh 的 -D + -A 模式）
    # 仅对实际存在的协议栈操作
    # ICMP 规则追加到链末尾（在默认策略之前，属于端口层）
    for cmd in $(get_active_cmds); do
        local proto=$([ "$cmd" = "iptables" ] && echo "icmp" || echo "icmpv6")
        local icmp_opt=$([ "$cmd" = "iptables" ] && echo "--icmp-type" || echo "--icmpv6-type")
        local icmp_type="echo-request"
        local icmp_reply="echo-reply"
        # 删除旧版全接口 ping 规则（兼容历史配置）
        $cmd -D INPUT -p $proto $icmp_opt $icmp_type -j ACCEPT 2>/dev/null || true
        $cmd -D OUTPUT -p $proto $icmp_opt $icmp_reply -j ACCEPT 2>/dev/null || true
        # 删除旧版指定公网接口的 ping 规则（幂等清理）
        $cmd -D INPUT -i $DEFAULT_ETH -p $proto $icmp_opt $icmp_type -j ACCEPT 2>/dev/null || true
        $cmd -D OUTPUT -o $DEFAULT_ETH -p $proto $icmp_opt $icmp_reply -j ACCEPT 2>/dev/null || true
        # 仅放行公网接口的 ping
        $cmd -A INPUT -i $DEFAULT_ETH -p $proto $icmp_opt $icmp_type -j ACCEPT
        $cmd -A OUTPUT -o $DEFAULT_ETH -p $proto $icmp_opt $icmp_reply -j ACCEPT
        local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
        echo -e "${GREEN}   ✅ ${label} 公网 PING 已允许（VPN/内网 ping 始终允许）${NC}"
    done
    save_rules
}

disable_ping() {
    # ⚠️ 此功能仅禁用公网接口的 PING！
    # VPN/内网 ping（tailscale0, easytier 等）由保命规则永久放行，p-off 不会删除它们。
    # 清理时两栈都尝试（安全清理历史规则），忽略错误
    for cmd in $(get_active_cmds); do
        local proto=$([ "$cmd" = "iptables" ] && echo "icmp" || echo "icmpv6")
        local icmp_opt=$([ "$cmd" = "iptables" ] && echo "--icmp-type" || echo "--icmpv6-type")
        # 删除旧版全接口 ping 规则（兼容历史配置）
        $cmd -D INPUT -p $proto $icmp_opt echo-request -j ACCEPT 2>/dev/null || true
        $cmd -D OUTPUT -p $proto $icmp_opt echo-reply -j ACCEPT 2>/dev/null || true
        # 删除当前公网接口 ping 规则
        $cmd -D INPUT -i $DEFAULT_ETH -p $proto $icmp_opt echo-request -j ACCEPT 2>/dev/null || true
        $cmd -D OUTPUT -o $DEFAULT_ETH -p $proto $icmp_opt echo-reply -j ACCEPT 2>/dev/null || true
        local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
        echo -e "${RED}   🔒 ${label} 公网 PING 已禁止（VPN/内网 ping 仍允许）${NC}"
    done
    save_rules
}

# ============================================================
# DOCKER-USER 链管理功能
# 
# ⚠️ 为什么需要 DOCKER-USER？
# Docker 自动管理的 FORWARD 链（DOCKER-ISOLATION、DOCKER 等子链）在流量
# 进入 INPUT 链之前就先匹配 FORWARD 链。1Panel 的子链（1PANEL_INPUT）
# 只能管控到达 INPUT 链的流量，无法管控 Docker 转发的流量。
#
# Docker 官方提供了 DOCKER-USER 子链作为用户自定义过滤的入口点，
# 它在 FORWARD 链中最先执行（早于 DOCKER-ISOLATION 和 DOCKER 链），
# 是唯一能安全管控 Docker 转发流量的地方。
#
# DOCKER-USER 链结构（从上到下匹配）：
#   1. 用户自定义过滤规则（DROP/REJECT/ACCEPT）
#   2. DDoS 限速规则（如果启用了 DDoS 防御）
#   3. RETURN（回到 FORWARD 链继续匹配 Docker 自管链）
#
# 管控原则：
#   - 在 RETURN 之前插入用户规则，优先于 Docker 自管链匹配
#   - DROP 规则拦截恶意流量，不让它进入 Docker 自管链
#   - ACCEPT 规则直接放行，跳过 Docker 自管链
#   - 不匹配用户规则的流量 RETURN 回 FORWARD 继续 Docker 正常流程
# ============================================================

# 在 DOCKER-USER 链中添加过滤规则
# 参数: <源IP> <端口> [协议] [动作]
# 例: docker-user-add 1.2.3.4 8080 tcp DROP
#     docker-user-add 0/0 3306 tcp DROP  (禁止外部访问 Docker 容器的 3306)
docker_user_add() {
    local src_ip="$1"
    local port="$2"
    local proto="${3:-tcp}"
    local action="${4:-DROP}"

    [ -z "$src_ip" ] && { echo -e "${RED}请提供源IP或网段${NC}"; return 1; }
    [ -z "$port" ] && { echo -e "${RED}请提供端口号或端口范围${NC}"; return 1; }
    validate_ip "$src_ip" || return 1
    validate_port "$port" || return 1
    validate_proto "$proto" || return 1
    validate_action "$action" || return 1

    local port_args=$(build_port_args "$port")
    local port_label=$port
    is_port_range "$port" && port_label="范围 ${port}"

    # 根据源 IP 判断使用哪个命令
    local cmds=()
    if [[ "$src_ip" == *:* ]]; then
        $HAS_V6 && cmds+=("ip6tables")
    elif [[ "$src_ip" == "0/0" || "$src_ip" == "0.0.0.0/0" ]]; then
        $HAS_V4 && cmds+=("iptables")
        $HAS_V6 && cmds+=("ip6tables")
    elif [[ "$src_ip" == "::/0" ]]; then
        $HAS_V6 && cmds+=("ip6tables")
    else
        $HAS_V4 && cmds+=("iptables")
    fi

    if [ ${#cmds[@]} -eq 0 ]; then
        echo -e "${YELLOW}   ⚠️  跳过：目标 IP 协议栈在本机不存在${NC}"
        return 0
    fi

    for cmd in "${cmds[@]}"; do
        # 确保 DOCKER-USER 链存在
        if ! $cmd -L DOCKER-USER -n &>/dev/null; then
            $cmd -N DOCKER-USER 2>/dev/null || true
            $cmd -I FORWARD -j DOCKER-USER 2>/dev/null || true
            $cmd -A DOCKER-USER -j RETURN 2>/dev/null || true
        fi

        # 先删除可能存在的同规格旧规则（幂等）
        $cmd -D DOCKER-USER -s "$src_ip" -p "$proto" $port_args -j "$action" 2>/dev/null || true

        # 插入到 RETURN 规则之前（在 DDoS 规则之后、RETURN 之前）
        # 找到 RETURN 行的位置，插入到其前面
        local return_pos=$($cmd -L DOCKER-USER -n --line-numbers 2>/dev/null | awk '/RETURN/{print $1; exit}')
        if [ -n "$return_pos" ]; then
            $cmd -I DOCKER-USER $return_pos -s "$src_ip" -p "$proto" $port_args -j "$action"
        else
            # 没有 RETURN 规则，追加到末尾
            $cmd -A DOCKER-USER -s "$src_ip" -p "$proto" $port_args -j "$action"
        fi
        local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
        echo -e "${GREEN}   ✅ ${label} DOCKER-USER 已添加: -s ${src_ip} -p ${proto} ${port_args} -j ${action}${NC}"
    done
    save_rules
}

# 删除 DOCKER-USER 链中的过滤规则
docker_user_del() {
    local src_ip="$1"
    local port="$2"
    local proto="${3:-tcp}"
    local action="${4:-DROP}"

    [ -z "$src_ip" ] && { echo -e "${RED}请提供源IP或网段${NC}"; return 1; }
    [ -z "$port" ] && { echo -e "${RED}请提供端口号或端口范围${NC}"; return 1; }
    validate_ip "$src_ip" || return 1
    validate_port "$port" || return 1

    local port_args=$(build_port_args "$port")
    local port_label=$port
    is_port_range "$port" && port_label="范围 ${port}"

    local cmds=()
    if [[ "$src_ip" == *:* ]]; then
        $HAS_V6 && cmds+=("ip6tables")
    elif [[ "$src_ip" == "0/0" || "$src_ip" == "0.0.0.0/0" ]]; then
        $HAS_V4 && cmds+=("iptables")
        $HAS_V6 && cmds+=("ip6tables")
    elif [[ "$src_ip" == "::/0" ]]; then
        $HAS_V6 && cmds+=("ip6tables")
    else
        $HAS_V4 && cmds+=("iptables")
    fi

    local deleted=false
    for cmd in "${cmds[@]}"; do
        # 尝试删除指定动作的规则
        if $cmd -D DOCKER-USER -s "$src_ip" -p "$proto" $port_args -j "$action" 2>/dev/null; then
            local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
            echo -e "${YELLOW}   🧹 ${label} DOCKER-USER 已删除: -s ${src_ip} -p ${proto} ${port_args} -j ${action}${NC}"
            deleted=true
        fi
        # 也尝试删除相反动作的规则（用户可能记错动作）
        local opposite_action
        [ "$action" = "DROP" ] && opposite_action="ACCEPT"
        [ "$action" = "ACCEPT" ] && opposite_action="DROP"
        if [ -n "$opposite_action" ]; then
            $cmd -D DOCKER-USER -s "$src_ip" -p "$proto" $port_args -j "$opposite_action" 2>/dev/null && deleted=true
        fi
    done
    if $deleted; then
        save_rules
    else
        echo -e "${RED}   ⚠️  DOCKER-USER 规则不存在${NC}"
    fi
}

# 查看 DOCKER-USER 链规则
docker_user_list() {
    echo -e "\n${BLUE}══════════════════ DOCKER-USER 链 (IPv4) ══════════════════${NC}"
    if $HAS_V4; then
        iptables -L DOCKER-USER -n -v --line-numbers 2>/dev/null || echo "  (链不存在)"
    else
        echo "  (本机无 IPv4 协议栈)"
    fi
    echo ""
    echo -e "${BLUE}══════════════════ DOCKER-USER 链 (IPv6) ══════════════════${NC}"
    if $HAS_V6; then
        ip6tables -L DOCKER-USER -n -v --line-numbers 2>/dev/null || echo "  (链不存在)"
    else
        echo "  (本机无 IPv6 协议栈)"
    fi
    echo ""
}

# 封锁指定 IP 对 Docker 容器的访问
docker_user_block_ip() {
    local ips=($@)
    [ ${#ips[@]} -eq 0 ] && { echo -e "${RED}请提供至少一个IP或IP段${NC}"; return 1; }
    for ip in "${ips[@]}"; do
        validate_ip "$ip" || continue
        local cmd="iptables"; [[ "$ip" == *:* ]] && cmd="ip6tables"
        if ! should_run_cmd "$cmd"; then
            echo -e "${YELLOW}   ⚠️  跳过 $ip：对应的 IP 协议栈在本机不存在${NC}"
            continue
        fi
        # 确保 DOCKER-USER 链存在
        if ! $cmd -L DOCKER-USER -n &>/dev/null; then
            $cmd -N DOCKER-USER 2>/dev/null || true
            $cmd -I FORWARD -j DOCKER-USER 2>/dev/null || true
            $cmd -A DOCKER-USER -j RETURN 2>/dev/null || true
        fi
        # 先删旧规则（幂等）
        $cmd -D DOCKER-USER -s "$ip" -j DROP 2>/dev/null || true
        $cmd -D DOCKER-USER -s "$ip" -j ACCEPT 2>/dev/null || true
        # 关键修复：DROP 插入到 RETURN 之后（allow 优先于 block）
        # allow-ip 的 ACCEPT 在 RETURN 之前，能正确放行特定 IP
        # block-ip 的 DROP 在 RETURN 之后，只影响未被 allow 放行的 IP
        local return_pos=$($cmd -L DOCKER-USER -n --line-numbers 2>/dev/null | awk '/RETURN/{print $1; exit}')
        if [ -n "$return_pos" ]; then
            $cmd -I DOCKER-USER $((return_pos + 1)) -s "$ip" -j DROP
        else
            $cmd -A DOCKER-USER -s "$ip" -j DROP
        fi
        echo -e "${RED}   🔒 DOCKER-USER 已封锁 IP: $ip（禁止访问所有 Docker 容器，allow 优先）${NC}"
    done
    save_rules
}

# 放行指定 IP 对 Docker 容器的访问（白名单优先）
docker_user_allow_ip() {
    local ips=($@)
    [ ${#ips[@]} -eq 0 ] && { echo -e "${RED}请提供至少一个IP或IP段${NC}"; return 1; }
    for ip in "${ips[@]}"; do
        validate_ip "$ip" || continue
        local cmd="iptables"; [[ "$ip" == *:* ]] && cmd="ip6tables"
        if ! should_run_cmd "$cmd"; then
            echo -e "${YELLOW}   ⚠️  跳过 $ip：对应的 IP 协议栈在本机不存在${NC}"
            continue
        fi
        if ! $cmd -L DOCKER-USER -n &>/dev/null; then
            $cmd -N DOCKER-USER 2>/dev/null || true
            $cmd -I FORWARD -j DOCKER-USER 2>/dev/null || true
            $cmd -A DOCKER-USER -j RETURN 2>/dev/null || true
        fi
        $cmd -D DOCKER-USER -s "$ip" -j DROP 2>/dev/null || true
        $cmd -D DOCKER-USER -s "$ip" -j ACCEPT 2>/dev/null || true
        local return_pos=$($cmd -L DOCKER-USER -n --line-numbers 2>/dev/null | awk '/RETURN/{print $1; exit}')
        if [ -n "$return_pos" ]; then
            $cmd -I DOCKER-USER $return_pos -s "$ip" -j ACCEPT
        else
            $cmd -A DOCKER-USER -s "$ip" -j ACCEPT
        fi
        echo -e "${GREEN}   ✅ DOCKER-USER 已放行 IP: $ip（允许访问所有 Docker 容器）${NC}"
    done
    save_rules
}

# 封锁外部访问 Docker 容器的指定端口
docker_user_block_port() {
    local ports=($@)
    [ ${#ports[@]} -eq 0 ] && { echo -e "${RED}请提供至少一个端口号或端口范围${NC}"; return 1; }
    for port in "${ports[@]}"; do
        validate_port "$port" || continue
        local port_args=$(build_port_args "$port")
        local port_label=$port
        is_port_range "$port" && port_label="范围 ${port}"
        for cmd in $(get_active_cmds); do
            if ! $cmd -L DOCKER-USER -n &>/dev/null; then
                $cmd -N DOCKER-USER 2>/dev/null || true
                $cmd -I FORWARD -j DOCKER-USER 2>/dev/null || true
                $cmd -A DOCKER-USER -j RETURN 2>/dev/null || true
            fi
            for proto in tcp udp; do
                # 先删旧规则（幂等）
                $cmd -D DOCKER-USER -p "$proto" $port_args -j DROP 2>/dev/null || true
                $cmd -D DOCKER-USER -p "$proto" $port_args -j ACCEPT 2>/dev/null || true
                # 关键修复：DROP 追加到 RETURN 之后（allow 优先于 block）
                # allow-port 的 ACCEPT 在 RETURN 之前，能正确放行特定 IP
                # block-port 的 DROP 在 RETURN 之后，只影响未被 allow 放行的流量
                local return_pos=$($cmd -L DOCKER-USER -n --line-numbers 2>/dev/null | awk '/RETURN/{print $1; exit}')
                if [ -n "$return_pos" ]; then
                    # RETURN 之后的第一个位置插入 DROP
                    $cmd -I DOCKER-USER $((return_pos + 1)) -p "$proto" $port_args -j DROP
                else
                    $cmd -A DOCKER-USER -p "$proto" $port_args -j DROP
                fi
                local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
                echo -e "${RED}   🔒 ${label} DOCKER-USER ${proto^^} ${port_label} 已封锁（allow 优先）${NC}"
            done
        done
    done
    save_rules
}

# 放行指定 IP 访问 Docker 容器的指定端口
docker_user_allow_port() {
    local src_ip="$1"
    local port="$2"
    local proto="${3:-tcp}"

    [ -z "$src_ip" ] && { echo -e "${RED}请提供源IP或网段${NC}"; return 1; }
    [ -z "$port" ] && { echo -e "${RED}请提供端口号或端口范围${NC}"; return 1; }
    validate_ip "$src_ip" || return 1
    validate_port "$port" || return 1
    validate_proto "$proto" || return 1

    local port_args=$(build_port_args "$port")
    local port_label=$port
    is_port_range "$port" && port_label="范围 ${port}"

    local cmd="iptables"; [[ "$src_ip" == *:* ]] && cmd="ip6tables"
    if ! should_run_cmd "$cmd"; then
        echo -e "${YELLOW}   ⚠️  跳过：对应的 IP 协议栈在本机不存在${NC}"
        return 0
    fi

    if ! $cmd -L DOCKER-USER -n &>/dev/null; then
        $cmd -N DOCKER-USER 2>/dev/null || true
        $cmd -I FORWARD -j DOCKER-USER 2>/dev/null || true
        $cmd -A DOCKER-USER -j RETURN 2>/dev/null || true
    fi
    # 先删旧规则（幂等）
    $cmd -D DOCKER-USER -s "$src_ip" -p "$proto" $port_args -j ACCEPT 2>/dev/null || true
    $cmd -D DOCKER-USER -s "$src_ip" -p "$proto" $port_args -j DROP 2>/dev/null || true
    local return_pos=$($cmd -L DOCKER-USER -n --line-numbers 2>/dev/null | awk '/RETURN/{print $1; exit}')
    if [ -n "$return_pos" ]; then
        $cmd -I DOCKER-USER $return_pos -s "$src_ip" -p "$proto" $port_args -j ACCEPT
    else
        $cmd -A DOCKER-USER -s "$src_ip" -p "$proto" $port_args -j ACCEPT
    fi
    local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
    echo -e "${GREEN}   ✅ ${label} DOCKER-USER 已放行: ${src_ip} → ${proto^^} ${port_label}${NC}"
    save_rules
}

show_rules() {
    echo -e "\n${BLUE}══════════════════ IPv4 INPUT 链 ══════════════════${NC}"
    if $HAS_V4; then
        iptables -L INPUT -n -v --line-numbers 2>/dev/null || echo "  (无规则)"
    else
        echo "  (本机无 IPv4 协议栈)"
    fi
    echo ""
    echo -e "${BLUE}══════════════════ IPv4 FORWARD 链 ════════════════${NC}"
    if $HAS_V4; then
        iptables -L FORWARD -n -v --line-numbers 2>/dev/null || echo "  (无规则)"
    else
        echo "  (本机无 IPv4 协议栈)"
    fi
    echo ""
    echo -e "${BLUE}══════════════════ IPv6 INPUT 链 ══════════════════${NC}"
    if $HAS_V6; then
        ip6tables -L INPUT -n -v --line-numbers 2>/dev/null || echo "  (无规则)"
    else
        echo "  (本机无 IPv6 协议栈)"
    fi
    echo ""
    echo -e "${BLUE}══════════════════ IPv6 FORWARD 链 ════════════════${NC}"
    if $HAS_V6; then
        ip6tables -L FORWARD -n -v --line-numbers 2>/dev/null || echo "  (无规则)"
    else
        echo "  (本机无 IPv6 协议栈)"
    fi
    echo ""
    echo -e "${BLUE}══════════════════ DDoS 子链 (IPv4) ══════════════════${NC}"
    if $HAS_V4; then
        iptables -L DDOS-PROTECT -n -v --line-numbers 2>/dev/null || echo "  (子链不存在)"
    else
        echo "  (本机无 IPv4 协议栈)"
    fi
    echo ""
    echo -e "${BLUE}══════════════════ DDoS 子链 (IPv6) ══════════════════${NC}"
    if $HAS_V6; then
        ip6tables -L DDOS-PROTECT -n -v --line-numbers 2>/dev/null || echo "  (子链不存在)"
    else
        echo "  (本机无 IPv6 协议栈)"
    fi
    echo ""
    echo -e "${BLUE}══════════════════ DOCKER-USER 链 (IPv4) ══════════════════${NC}"
    if $HAS_V4; then
        iptables -L DOCKER-USER -n -v --line-numbers 2>/dev/null || echo "  (链不存在)"
    else
        echo "  (本机无 IPv4 协议栈)"
    fi
    echo ""
    echo -e "${BLUE}══════════════════ DOCKER-USER 链 (IPv6) ══════════════════${NC}"
    if $HAS_V6; then
        ip6tables -L DOCKER-USER -n -v --line-numbers 2>/dev/null || echo "  (链不存在)"
    else
        echo "  (本机无 IPv6 协议栈)"
    fi
    echo ""
}

# ============================================================
# 规则纠错机制（交互式）
# ============================================================
# 检测规则位置是否正确，并提供交互式修复功能
# 原则：
#   1. 不删除外部规则，只调整位置或标记警告
#   2. 保留管理子链跳转（ts-input, et-input, 1PANEL_INPUT等）
#   3. 优先保证安全规则（lo, conntrack）的正确顺序
#   4. 智能判断目标位置，用户确认后再执行

# 定义规则类型和期望位置
# 层1: 管理子链跳转（第三方自动注入，置顶）
# 层2: 保命规则 (lo, conntrack, $METADATA_CIDR, VPN/内网ICMP, IPv6基础)
# 层3: DDOS-PROTECT 子链跳转
# 层4: IP 黑名单 DROP 规则
# 层5: IP 白名单 ACCEPT 规则
# 层6: 端口规则 (ACCEPT/DROP)

repair_rules() {
    # 移动规则到指定位置的辅助函数
    # 参数: $1=命令(iptables/ip6tables), $2=规则号, $3=目标位置, $4=提示消息
    # 返回: 0=成功, 1=失败
    move_rule_to_position() {
        local cmd="$1"
        local rule_num="$2"
        local target_pos="$3"
        local prompt_msg="$4"
        
        echo -e "${BLUE}  ${prompt_msg}${NC}"
        
        # 获取完整规则并移动（-S 输出格式: "-A INPUT ..."）
        # 修复: 使用 sed 获取指定行,而非错误的 awk 逻辑
        local full_rule=$($cmd -S INPUT 2>/dev/null | sed -n "${rule_num}p" | sed 's/^-A INPUT //')
        if [ -n "$full_rule" ]; then
            # 删除原规则（使用规则内容而非行号，因为移动后行号会变化）
            $cmd -D INPUT $full_rule 2>/dev/null || true
            # 插入到目标位置
            if [ "$target_pos" = "append" ]; then
                $cmd -A INPUT $full_rule
            else
                $cmd -I INPUT $target_pos $full_rule
            fi
            
            # 根据目标位置类型输出不同的成功消息
            if [ "$target_pos" = "append" ]; then
                echo -e "${GREEN}  ✅ 规则已移动到链末尾${NC}"
            else
                echo -e "${GREEN}  ✅ 规则已移动到第 ${target_pos} 行${NC}"
            fi
            return 0
        else
            echo -e "${RED}  ❌ 无法获取规则详情，跳过${NC}"
            return 1
        fi
    }

    echo -e "${GREEN}🔧 规则顺序检测与修复工具${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}检测规则：${NC}"
    echo "  - 保命规则应在 DDOS-PROTECT 之前"
    echo "  - DDOS-PROTECT 应在 IP 规则之前"
    echo "  - IP 黑名单应在 IP 白名单之前"
    echo "  - 端口规则应在 IP 规则之后"
    echo ""

    local errors_found=0
    local repairs_made=0
    local pending_repairs=()

    for cmd in $(get_active_cmds); do
        local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")
        echo -e "${BLUE}正在检测 ${label} INPUT 链...${NC}"

        # 获取当前规则列表（带行号）
        local rules=$($cmd -L INPUT -n --line-numbers 2>/dev/null)
        local total_lines=$(echo "$rules" | wc -l)

        # 找到关键标记位置
        local lo_pos=$(echo "$rules" | awk '/lo.*ACCEPT/{print $1; exit}')
        local ct_pos=$(echo "$rules" | awk '/conntrack.*ESTABLISHED/{print $1; exit}')
        local ddos_pos=$(echo "$rules" | awk '/DDOS-PROTECT/{print $1; exit}')

        # 分析每个规则
        local line_num=1
        while read -r rule; do
            [ -z "$rule" ] && { line_num++; continue; }
            
            # 跳过标题行
            echo "$rule" | grep -q "^Chain\|^target\|^-" && { line_num++; continue; }

            local rule_num=$(echo "$rule" | awk '{print $1}')
            local target=$(echo "$rule" | awk '{print $4}')
            local prot=$(echo "$rule" | awk '{print $2}')
            local opt=$(echo "$rule" | awk '{print $3}')
            local src=$(echo "$rule" | awk '{print $5}')
            local dport=$(echo "$rule" | grep -oE "dpt:[0-9:]+" | cut -d: -f2)
            
            # 构建规则描述
            local rule_desc="$rule_num: $target $prot"
            [ -n "$src" ] && rule_desc="$rule_desc src=$src"
            [ -n "$dport" ] && rule_desc="$rule_desc dport=$dport"

            # 检测规则类型并判断位置是否正确
            local expected_layer=""
            local current_layer=""
            local should_move=false
            local target_pos=""

            # 判断规则类型
            if echo "$rule" | grep -q "lo "; then
                expected_layer="层2（保命规则）"
                # lo 应在最前面（管理子链之后）
                if [ -n "$lo_pos" ] && [ "$lo_pos" -gt 3 ]; then
                    should_move=true
                    target_pos=2  # 插入到第2行（管理子链之后）
                fi
            elif echo "$rule" | grep -q "conntrack"; then
                expected_layer="层2（保命规则）"
                # conntrack 应在 lo 之后、DDOS-PROTECT 之前
                if [ -n "$ct_pos" ] && [ -n "$ddos_pos" ] && [ "$ct_pos" -gt "$ddos_pos" ]; then
                    should_move=true
                    target_pos=$((ddos_pos))
                fi
            elif echo "$rule" | grep -q "DDOS-PROTECT"; then
                expected_layer="层3（DDoS防御）"
                # DDOS-PROTECT 应在保命规则之后、IP规则之前
                :  # 位置检测复杂，暂不处理
            elif [ "$target" = "DROP" ] && [ -n "$src" ] && [ "$src" != "0.0.0.0/0" ] && [ "$src" != "::/0" ]; then
                expected_layer="层4（IP黑名单）"
                # IP黑名单应在 DDOS-PROTECT 之后
                if [ -n "$ddos_pos" ] && [ "$rule_num" -lt "$((ddos_pos + 1))" ]; then
                    should_move=true
                    target_pos=$((ddos_pos + 1))
                fi
            elif [ "$target" = "ACCEPT" ] && [ -n "$src" ] && [ "$src" != "0.0.0.0/0" ] && [ "$src" != "::/0" ]; then
                expected_layer="层5（IP白名单）"
                # IP白名单应在 DDOS-PROTECT 之后、端口规则之前
                if [ -n "$ddos_pos" ] && [ "$rule_num" -lt "$((ddos_pos + 1))" ]; then
                    should_move=true
                    target_pos=$((ddos_pos + 1))
                fi
            elif [ -n "$dport" ]; then
                expected_layer="层6（端口规则）"
                # 端口规则应在 DDOS-PROTECT 之后
                if [ -n "$ddos_pos" ] && [ "$rule_num" -lt "$((ddos_pos + 1))" ]; then
                    should_move=true
                    target_pos=$((ddos_pos + 1))
                fi
            fi

            # 如果检测到位置错误
            if $should_move; then
                errors_found=$((errors_found + 1))
                echo -e "${RED}   ⚠️  规则位置异常${NC}: $rule_desc"
                echo -e "${YELLOW}      当前位置: 第${rule_num}行, 期望位置: ${expected_layer}（建议插入到第${target_pos}行）${NC}"
                
                # 添加到待修复列表
                pending_repairs+=("$cmd|$rule_num|$target_pos|$rule_desc")
            fi

            line_num=$((line_num + 1))
        done <<< "$rules"
    done

    echo ""
    if [ $errors_found -eq 0 ]; then
        echo -e "${GREEN}✅ 未检测到规则位置异常${NC}"
        return 0
    fi

    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}检测到 ${errors_found} 个规则位置异常${NC}"
    echo ""

    # 交互式修复
    for repair in "${pending_repairs[@]}"; do
        IFS='|' read -r cmd rule_num target_pos rule_desc <<< "$repair"
        local label=$([ "$cmd" = "iptables" ] && echo "IPv4" || echo "IPv6")

        echo -e "${RED}待修复: ${label} ${rule_desc}${NC}"
        echo -e "${YELLOW}  建议移动到第 ${target_pos} 行${NC}"
        echo ""
        echo "  请选择操作:"
        echo "    [Y/y] 确认移动到建议位置"
        echo "    [S/s] 选择目标层级"
        echo "    [N/n] 跳过此规则"
        echo "    [A/a] 全部跳过"
        echo ""
        read -e -p "  输入选择 [Y/S/N/A]: " choice

        case "$choice" in
            [Yy])
                move_rule_to_position "$cmd" "$rule_num" "$target_pos" "正在移动规则..."
                repairs_made=$((repairs_made + 1))
                ;;
            [Ss])
                echo ""
                echo "  可用目标层级:"
                echo "    1. 层1 - 管理/VPN端口（DDOS-PROTECT之前）"
                echo "    2. 层2 - 保命规则区"
                echo "    3. 层4 - IP黑名单区（DDOS-PROTECT之后）"
                echo "    4. 层5 - IP白名单区"
                echo "    5. 层6 - 端口规则区（链末尾）"
                read -e -p "  选择目标层级 [1-5]: " layer_choice
                case "$layer_choice" in
                    1)
                        target_pos=$(get_pre_ddos_pos "$cmd" INPUT)
                        ;;
                    2)
                        target_pos=2
                        ;;
                    3|4)
                        target_pos=$(get_ddos_pos "$cmd" INPUT)
                        ;;
                    5)
                        target_pos="append"
                        ;;
                    *)
                        echo -e "${RED}  ❌ 无效选择，跳过${NC}"
                        continue
                        ;;
                esac
                move_rule_to_position "$cmd" "$rule_num" "$target_pos" "正在移动规则到选定位置..."
                repairs_made=$((repairs_made + 1))
                ;;
            [Nn])
                echo -e "${YELLOW}  ⏭️  跳过此规则${NC}"
                ;;
            [Aa])
                echo -e "${YELLOW}  ⏭️  跳过所有剩余规则${NC}"
                break
                ;;
            *)
                echo -e "${RED}  ❌ 无效输入，跳过${NC}"
                ;;
        esac
        echo ""
    done

    if [ $repairs_made -gt 0 ]; then
        save_rules
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}🎉 修复完成！共修复 ${repairs_made} 个规则${NC}"
        echo -e "${BLUE}规则已持久化${NC}"
    else
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}未进行任何修复${NC}"
    fi
}

# ============================================================
# 交互菜单
# ============================================================
interactive_menu() {
    while true; do
        clear
        echo -e "${GREEN}🛡️  防火墙管理 (默认网卡: ${DEFAULT_ETH})${NC}"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "  ── 端口 ──────────────────────────────"
        echo "  1. 开放端口              2. 关闭端口"
        echo "     （支持范围格式如 80:100）"
        echo ""
        echo "  ── VPN/管理端口（绕过DDoS限速）──────"
        echo "  17. 开放管理端口         18. 关闭管理端口"
        echo "     （插入到DDOS-PROTECT之前）"
        echo ""
        echo "  ── IP ─────────────────────────────────"
        echo "  3. IP 白名单             4. IP 黑名单"
        echo "  5. 清除指定 IP 规则"
        echo ""
        echo "  ── 网卡规则 ──────────────────────────"
        echo "  6. 添加网卡规则          7. 删除网卡规则"
        echo "  8. 网卡放行端口          9. 网卡拒绝端口"
        echo "  10. 查看可用网卡"
        echo ""
        echo "  ── 高级 ──────────────────────────────"
        echo "  11. 启用 DDoS 防御       12. 关闭 DDoS 防御"
        echo "  13. 允许公网 PING          14. 禁止公网 PING"
        echo "     （VPN/内网 ping 默认放行，不受此开关影响）"
        echo "  15. 查看全部规则          16. 规则顺序修复"
        echo ""
        echo "  ── DOCKER-USER（管控 Docker 转发流量）──"
        echo "  19. 封锁容器端口         20. 放行容器端口"
        echo "  21. 封锁容器 IP          22. 放行容器 IP"
        echo "  23. 查看 DOCKER-USER 链"
        echo ""
        echo "  0. 退出"
        echo ""
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        read -e -p "请输入你的选择: " choice

        case $choice in
            1)
                echo ""; read -e -p "端口号/端口范围（多个空格分隔，范围用 80:100）: " ports
                echo ""; [ -n "$ports" ] && open_port $ports
                echo ""; read -e -p "按回车继续..." _ ;;
            2)
                echo ""; read -e -p "端口号/端口范围（多个空格分隔，范围用 80:100）: " ports
                echo ""; [ -n "$ports" ] && close_port $ports
                echo ""; read -e -p "按回车继续..." _ ;;
            3)
                echo ""; read -e -p "放行的 IP/IP段（多个空格分隔）: " ips
                echo ""; [ -n "$ips" ] && allow_ip $ips
                echo ""; read -e -p "按回车继续..." _ ;;
            4)
                echo ""; read -e -p "封锁的 IP/IP段（多个空格分隔）: " ips
                echo ""; [ -n "$ips" ] && block_ip $ips
                echo ""; read -e -p "按回车继续..." _ ;;
            5)
                echo ""; read -e -p "清除的 IP（多个空格分隔）: " ips
                echo ""; [ -n "$ips" ] && clear_ip $ips
                echo ""; read -e -p "按回车继续..." _ ;;
            6)
                echo ""
                echo -e "${BLUE}添加网卡规则（类似: iptables -A INPUT -s 100.64.0.0/10 ! -i tailscale0 -j DROP）${NC}"
                echo ""
                list_nics
                echo ""
                read -e -p "规则链 [INPUT/FORWARD, 默认: INPUT]: " chain
                chain="${chain:-INPUT}"
                read -e -p "网卡名 [如 tailscale0]: " nic
                read -e -p "方向 [i=入站/o=出站, 默认: i]: " direction
                direction="${direction:-i}"
                read -e -p "源 IP 或网段 [如 100.64.0.0/10]: " src_ip
                read -e -p "端口 [可选, 直接回车跳过]: " port
                local proto=""
                if [ -n "$port" ]; then
                    read -e -p "协议 [tcp/udp/all, 默认: tcp]: " proto
                    proto="${proto:-tcp}"
                fi
                read -e -p "动作 [ACCEPT/DROP/REJECT/RETURN, 默认: ACCEPT]: " action
                action="${action:-ACCEPT}"
                echo ""
                nic_rule_add "$chain" "$nic" "$direction" "$src_ip" "$port" "$proto" "$action"
                echo ""; read -e -p "按回车继续..." _ ;;
            7)
                echo ""
                echo -e "${RED}删除网卡规则${NC}"
                echo ""
                read -e -p "规则链 [INPUT/FORWARD, 默认: INPUT]: " chain
                chain="${chain:-INPUT}"
                read -e -p "网卡名: " nic
                read -e -p "方向 [i/o, 默认: i]: " direction
                direction="${direction:-i}"
                read -e -p "源 IP 或网段: " src_ip
                read -e -p "端口 [可选, 直接回车跳过]: " port
                local proto=""
                if [ -n "$port" ]; then
                    read -e -p "协议 [tcp/udp/all, 默认: tcp]: " proto
                    proto="${proto:-tcp}"
                fi
                read -e -p "动作 [ACCEPT/DROP/REJECT/RETURN, 默认: ACCEPT]: " action
                action="${action:-ACCEPT}"
                echo ""
                nic_rule_del "$chain" "$nic" "$direction" "$src_ip" "$port" "$proto" "$action"
                echo ""; read -e -p "按回车继续..." _ ;;
            8)
                echo ""; list_nics; echo ""
                read -e -p "网卡名 [默认: ${DEFAULT_ETH}]: " nic
                nic="${nic:-$DEFAULT_ETH}"
                read -e -p "端口号/端口范围（如 8080 或 80:100）: " port
                read -e -p "协议 [tcp/udp/both, 默认: both]: " proto
                proto="${proto:-both}"
                echo ""; [ -n "$port" ] && nic_allow_port "$nic" "$port" "$proto"
                echo ""; read -e -p "按回车继续..." _ ;;
            9)
                echo ""; list_nics; echo ""
                read -e -p "网卡名 [默认: ${DEFAULT_ETH}]: " nic
                nic="${nic:-$DEFAULT_ETH}"
                read -e -p "端口号/端口范围（如 8080 或 80:100）: " port
                read -e -p "协议 [tcp/udp/both, 默认: both]: " proto
                proto="${proto:-both}"
                echo ""; [ -n "$port" ] && nic_block_port "$nic" "$port" "$proto"
                echo ""; read -e -p "按回车继续..." _ ;;
            10)
                echo ""; list_nics; echo ""
                read -e -p "按回车继续..." _ ;;
            11) echo ""; enable_ddos; echo ""; read -e -p "按回车继续..." _ ;;
            12) echo ""; disable_ddos; echo ""; read -e -p "按回车继续..." _ ;;
            13) echo ""; enable_ping; echo ""; read -e -p "按回车继续..." _ ;;
            14) echo ""; disable_ping; echo ""; read -e -p "按回车继续..." _ ;;
            15) show_rules; echo ""; read -e -p "按回车继续..." _ ;;
            16) echo ""; repair_rules; echo ""; read -e -p "按回车继续..." _ ;;
            17)
                echo ""; read -e -p "管理端口号/端口范围（多个空格分隔，如 41010 41020）: " ports
                echo ""; [ -n "$ports" ] && open_port_pre_ddos $ports
                echo ""; read -e -p "按回车继续..." _ ;;
            18)
                echo ""; read -e -p "关闭管理端口号/端口范围（多个空格分隔）: " ports
                echo ""; [ -n "$ports" ] && close_port_pre_ddos $ports
                echo ""; read -e -p "按回车继续..." _ ;;
            19)
                echo ""; echo -e "${BLUE}封锁外部访问 Docker 容器的指定端口${NC}"; echo ""
                read -e -p "容器端口/端口范围（多个空格分隔，如 3306 6379）: " ports
                echo ""; [ -n "$ports" ] && docker_user_block_port $ports
                echo ""; read -e -p "按回车继续..." _ ;;
            20)
                echo ""; echo -e "${BLUE}放行指定 IP 访问 Docker 容器的指定端口${NC}"; echo ""
                read -e -p "源 IP/网段（如 1.2.3.4 或 10.0.0.0/8）: " src_ip
                read -e -p "容器端口/端口范围: " port
                read -e -p "协议 [tcp/udp, 默认: tcp]: " proto
                proto="${proto:-tcp}"
                echo ""; [ -n "$src_ip" ] && [ -n "$port" ] && docker_user_allow_port "$src_ip" "$port" "$proto"
                echo ""; read -e -p "按回车继续..." _ ;;
            21)
                echo ""; echo -e "${BLUE}封锁指定 IP 访问所有 Docker 容器${NC}"; echo ""
                read -e -p "IP/IP段（多个空格分隔）: " ips
                echo ""; [ -n "$ips" ] && docker_user_block_ip $ips
                echo ""; read -e -p "按回车继续..." _ ;;
            22)
                echo ""; echo -e "${BLUE}放行指定 IP 访问所有 Docker 容器${NC}"; echo ""
                read -e -p "IP/IP段（多个空格分隔）: " ips
                echo ""; [ -n "$ips" ] && docker_user_allow_ip $ips
                echo ""; read -e -p "按回车继续..." _ ;;
            23)
                echo ""; docker_user_list; read -e -p "按回车继续..." _ ;;
            0)
                echo -e "${GREEN}👋 再见！${NC}"; exit 0 ;;
            *)
                echo -e "${RED}无效选项${NC}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 命令行模式入口（setfirewall 子命令）
# ============================================================
run_cli() {
    case "$1" in
        open)             shift; open_port $@ ;;
        close)            shift; close_port $@ ;;
        open-pre-ddos)    shift; open_port_pre_ddos $@ ;;
        close-pre-ddos)   shift; close_port_pre_ddos $@ ;;
        allow)            shift; allow_ip $@ ;;
        block)            shift; block_ip $@ ;;
        clearip)          shift; clear_ip $@ ;;
        nic-add)          shift; nic_rule_add $@ ;;
        nic-del)          shift; nic_rule_del $@ ;;
        nic-allow)        shift; nic_allow_port $@ ;;
        nic-block)        shift; nic_block_port $@ ;;
        ddos-on)          enable_ddos ;;
        ddos-off)         disable_ddos ;;
        p-on)             enable_ping ;;
        p-off)            disable_ping ;;
        show|list)        show_rules ;;
        nics)             list_nics ;;
        docker-block-port)  shift; docker_user_block_port $@ ;;
        docker-allow-port)  shift; docker_user_allow_port $@ ;;
        docker-block-ip)    shift; docker_user_block_ip $@ ;;
        docker-allow-ip)    shift; docker_user_allow_ip $@ ;;
        docker-add)         shift; docker_user_add $@ ;;
        docker-del)         shift; docker_user_del $@ ;;
        docker-list)        docker_user_list ;;
        repair)           repair_rules ;;
        *)
            echo "用法: setfirewall {命令} [参数...]"
            echo ""
            echo "  端口:   open <端口...>           开放端口 (双栈, 支持范围如 80:100)"
            echo "          close <端口...>          关闭端口 (支持范围如 80:100)"
            echo ""
            echo "  VPN/管理端口（绕过DDoS限速，插入到DDOS-PROTECT之前）:"
            echo "          open-pre-ddos <端口...>  开放管理端口 (VPN监听端口等)"
            echo "          close-pre-ddos <端口...> 关闭管理端口"
            echo ""
            echo "  IP:     allow <IP...>            IP 白名单"
            echo "          block <IP...>            IP 黑名单"
            echo "          clearip <IP...>          清除 IP 规则"
            echo ""
            echo "  网卡:   nic-add <链> <网卡> <i/o> <源IP> [端口] [协议] [动作]"
            echo "          例: setfirewall nic-add INPUT tailscale0 i 100.64.0.0/10 \"\" \"\" DROP"
            echo "          例: setfirewall nic-add INPUT tailscale0 i 0/0 ${TAILSCALE_PORT} udp ACCEPT"
            echo "          nic-del <链> <网卡> <i/o> <源IP> [端口] [协议] [动作]"
            echo "          nic-allow <网卡> <端口/端口范围> [tcp|udp|both]"
            echo "          nic-block <网卡> <端口/端口范围> [tcp|udp|both]"
            echo "          nics                      查看网卡"
            echo ""
            echo "  高级:   ddos-on / ddos-off       DDoS 防御开关"
            echo "          p-on / p-off             公网 PING 开关（VPN/内网 ping 默认放行）"
            echo "          show                     查看规则"
            echo "          repair                   检测并修复规则顺序（交互式）"
            echo ""
            echo "  DOCKER-USER (管控 Docker 转发流量):"
            echo "          docker-block-port <端口..>  封锁外部访问容器端口"
            echo "          docker-allow-port <IP> <端口> [tcp|udp]  放行 IP 访问容器端口"
            echo "          docker-block-ip <IP..>    封锁 IP 访问所有容器"
            echo "          docker-allow-ip <IP..>    放行 IP 访问所有容器"
            echo "          docker-add <IP> <端口> [协议] [动作]  自定义容器过滤规则"
            echo "          docker-del <IP> <端口> [协议] [动作]  删除容器过滤规则"
            echo "          docker-list               查看 DOCKER-USER 链"
            echo ""
            echo "  无参数运行进入交互菜单"
            exit 1 ;;
    esac
    exit 0
}

# ============================================================
# 模式路由：setfirewall → 管理菜单，其他 → 初始化
# ============================================================
# 在进入任何模式之前，先检测协议栈
detect_ip_stack

if [ "$SCRIPT_NAME" = "setfirewall" ]; then
    # --- setfirewall 模式：防火墙管理 ---
    if [ $# -gt 0 ]; then
        run_cli "$@"
    else
        interactive_menu
    fi
    exit 0
fi

# ============================================================
# 以下为初始化模式（ocl-firewall-ini.sh）
# ============================================================

set -e

# 解析初始化参数（覆盖常量默认值）
parse_init_args "$@"

# ============================================================
# 自动检测阶段（仅在初始化模式下执行）
# ============================================================

echo -e "${GREEN}🔍 自动检测系统端口...${NC}"

# 自动检测 SSH 端口（仅在未通过参数指定时）
if [[ "$1" != --ssh-port=* ]]; then
    DETECTED_SSH_PORT=$(auto_detect_ssh_port)
    if [ -n "$DETECTED_SSH_PORT" ]; then
        SSH_PORT="$DETECTED_SSH_PORT"
        echo -e "${BLUE}   ✅ 自动检测到 SSH 端口: ${SSH_PORT}${NC}"
    fi
fi

# 自动检测 1Panel 端口（仅在 1Panel 运行时检测）
if is_1panel_running; then
    DETECTED_1PANEL_PORTS=$(auto_detect_1panel_ports)
    if [ -n "$DETECTED_1PANEL_PORTS" ]; then
        # 将 1Panel 端口添加到 PORTS 数组
        for port in $DETECTED_1PANEL_PORTS; do
            # 排除已存在的端口
            if [[ ! " ${PORTS[@]} " =~ " ${port} " ]]; then
                PORTS+=("$port")
                echo -e "${BLUE}   ✅ 自动检测到 1Panel 端口: ${port}${NC}"
            fi
        done
    else
        echo -e "${YELLOW}   ⚠️  1Panel 运行中但无法检测到端口（将跳过）${NC}"
    fi
else
    echo -e "${BLUE}   ℹ️  1Panel 未运行，跳过 1Panel 端口检测${NC}"
fi

# 自动检测已放行的其他端口（保留非服务管理的端口）
DETECTED_OTHER_PORTS=$(auto_detect_existing_ports)
if [ -n "$DETECTED_OTHER_PORTS" ]; then
    for port in $DETECTED_OTHER_PORTS; do
        # 排除已存在的端口
        if [[ ! " ${PORTS[@]} " =~ " ${port} " ]]; then
            PORTS+=("$port")
            echo -e "${BLUE}   ✅ 自动检测到已放行端口: ${port}${NC}"
        fi
    done
fi

# 构建完整端口列表：业务端口 + SSH 端口
ALL_PORTS=("${SSH_PORT}" "${PORTS[@]}")

# 协议栈检测已在模式路由前完成，这里输出检测结果
echo -e "${GREEN}🚀 Oracle Cloud Ubuntu 24.04 双栈防火墙初始化${NC}"
if $HAS_V4 && $HAS_V6; then
    echo -e "${BLUE}   ℹ️  检测到双栈环境（IPv4 + IPv6）${NC}"
elif $HAS_V4; then
    echo -e "${BLUE}   ℹ️  检测到纯 IPv4 环境（跳过所有 IPv6 规则）${NC}"
elif $HAS_V6; then
    echo -e "${BLUE}   ℹ️  检测到纯 IPv6 环境（跳过所有 IPv4 规则）${NC}"
fi

# 输出当前使用的常量值（方便审查）
echo -e "${BLUE}   ℹ️  初始化参数:${NC}"
echo -e "${BLUE}      SSH 端口: ${SSH_PORT}${NC}"
echo -e "${BLUE}      业务端口: ${PORTS[*]}${NC}"
echo -e "${BLUE}      全部端口: ${ALL_PORTS[*]}${NC}"
echo -e "${BLUE}      Tailscale 端口: ${TAILSCALE_PORT}${NC}"
echo -e "${BLUE}      元数据 CIDR: ${METADATA_CIDR}${NC}"
echo -e "${BLUE}      默认网卡: ${DEFAULT_ETH}${NC}"
echo -e "${BLUE}      DDoS 防御: ${ENABLE_DDOS_DEFENSE}${NC}"
if [ "$ENABLE_DDOS_DEFENSE" = "true" ]; then
    echo -e "${BLUE}      SYN 限速: ${DDOS_SYN_RATE}/s (burst ${DDOS_SYN_BURST})${NC}"
    echo -e "${BLUE}      UDP 限速: ${DDOS_UDP_RATE}/s${NC}"
fi

# ------------------------------------------------------------
# 0. 清理第三方防火墙，确保只使用 iptables
# ------------------------------------------------------------
echo -e "${GREEN}[0/8] 清理第三方防火墙（ufw/nftables 等）...${NC}"

# 停止并卸载 ufw（彻底移除，防止干扰我们的 iptables 规则）
# 注意：新版本 Ubuntu 使用 nftables 底层，iptables 通过兼容层写入 nftables
# 我们使用 iptables 管理规则即可，不需要动 nftables
if command -v ufw &>/dev/null; then
    echo -e "${BLUE}   ℹ️  检测到 ufw，正在卸载...${NC}"
    ufw --force disable 2>/dev/null || true
    systemctl stop ufw 2>/dev/null || true
    systemctl disable ufw 2>/dev/null || true
    apt-get purge -y -qq ufw 2>/dev/null || true
    echo -e "${BLUE}   ✅ ufw 已卸载${NC}"
else
    echo -e "${BLUE}   ℹ️  未检测到 ufw，跳过${NC}"
fi

echo -e "${BLUE}   ✅ 将使用 iptables 管理防火墙规则（底层为 nftables）${NC}"

# ------------------------------------------------------------
# 1. 安装必要组件（自动检测已安装的包，避免重复安装）
# ------------------------------------------------------------
echo -e "${GREEN}[1/8] 安装 iptables 持久化组件及 curl...${NC}"
export DEBIAN_FRONTEND=noninteractive

# 需要安装的包列表
REQUIRED_PKGS="iptables iptables-persistent curl"
MISSING_PKGS=""

for pkg in $REQUIRED_PKGS; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        echo -e "${BLUE}   ℹ️  ${pkg} 已安装，跳过${NC}"
    else
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done

if [ -n "$MISSING_PKGS" ]; then
    echo -e "${BLUE}   ℹ️  正在安装缺失的包:$MISSING_PKGS${NC}"
    apt-get update -qq
    apt-get install -y -qq $MISSING_PKGS > /dev/null
    echo -e "${GREEN}   ✅ 缺失包安装完成${NC}"
else
    echo -e "${GREEN}   ✅ 所有依赖已满足，无需安装${NC}"
fi
echo -e "${BLUE}   ℹ️  检测到默认网卡: ${DEFAULT_ETH}${NC}"

# ------------------------------------------------------------
# 2. 清空旧规则（先全开放防断连，再清空，最后设置默认DROP）
# ------------------------------------------------------------
echo -e "${GREEN}[2/8] 清空残留防火墙规则（先全开放防断连）${NC}"

TAILSCALE_WAS_ACTIVE=false
if systemctl is-active --quiet tailscaled 2>/dev/null; then
    TAILSCALE_WAS_ACTIVE=true
    echo -e "${BLUE}   ℹ️  检测到 Tailscale 正在运行，将保留其状态并在规则重建后恢复${NC}"
fi

PANEL_WAS_ACTIVE=false
if systemctl is-active --quiet 1panel 2>/dev/null; then
    PANEL_WAS_ACTIVE=true
    echo -e "${BLUE}   ℹ️  检测到 1Panel 正在运行，将在规则重建后恢复${NC}"
fi

NETBIRD_WAS_ACTIVE=false
if systemctl is-active --quiet netbird 2>/dev/null; then
    NETBIRD_WAS_ACTIVE=true
    echo -e "${BLUE}   ℹ️  检测到 NetBird 正在运行，将保留其状态并在规则重建后恢复${NC}"
fi

# ⚠️ 防断连关键步骤：先设置默认策略为 ACCEPT（全开放），再清空规则
# 这样在清空和重建规则的过程中不会导致 SSH 断连
iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
$HAS_V6 && { ip6tables -P INPUT ACCEPT; ip6tables -P FORWARD ACCEPT; ip6tables -P OUTPUT ACCEPT; }

# 清空所有规则和自定义链
iptables -F; iptables -X; iptables -t nat -F; iptables -t mangle -F; iptables -t raw -F
$HAS_V6 && { ip6tables -F; ip6tables -X; ip6tables -t nat -F; ip6tables -t mangle -F; ip6tables -t raw -F; }

# ------------------------------------------------------------
# 3. 系统保命规则（lo、conntrack、元数据、IPv6基础）
# ------------------------------------------------------------
echo -e "${GREEN}[3/8] 配置保命规则（lo、conntrack、元数据、VPN/内网ICMP、IPv6基础）${NC}"

# ⚠️ 规则顺序至关重要！iptables 从上到下匹配，先匹配先生效
# 初始化阶段规则构建顺序：
#   lo ACCEPT → conntrack ACCEPT → 元数据 → VPN/内网ICMP → IPv6基础 → DDoS限速 → 端口ACCEPT → 默认DROP
# 后续第三方服务（1Panel/Tailscale 等）重启后会自动将子链跳转置顶插入到 INPUT 链最前方，
# EasyTier 脚本会将 et-input 插入到保命规则之后、DDOS-PROTECT 之前，
# 不影响我们的自定义规则顺序（保命规则→管理子链→DDOS-PROTECT→IP规则→端口规则→默认DROP）

for cmd in $(get_active_cmds); do
    $cmd -A INPUT -i lo -j ACCEPT
    $cmd -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done

$HAS_V4 && { iptables -A INPUT -s "$METADATA_CIDR" -j ACCEPT; iptables -A OUTPUT -d "$METADATA_CIDR" -j ACCEPT; }

# VPN/内网 ping 默认放行（保命规则，不受 p-on/p-off 控制）
# 这些规则在 conntrack 和元数据之后、DDOS-PROTECT 之前
# p-on/p-off 只管控公网接口的 ping，VPN ping 始终允许
VPN_NICS="tailscale0 easytier wt0"
for nic in $VPN_NICS; do
    if ip link show "$nic" &>/dev/null; then
        # 网卡存在时添加 ICMP 放行
        $HAS_V4 && {
            iptables -A INPUT -i "$nic" -p icmp --icmp-type echo-request -j ACCEPT
            iptables -A OUTPUT -o "$nic" -p icmp --icmp-type echo-reply -j ACCEPT
        }
        $HAS_V6 && {
            ip6tables -A INPUT -i "$nic" -p icmpv6 --icmpv6-type echo-request -j ACCEPT
            ip6tables -A OUTPUT -o "$nic" -p icmpv6 --icmpv6-type echo-reply -j ACCEPT
        }
        echo -e "${BLUE}   ✅ VPN 网卡 $nic ICMP 已永久放行（不受 p-off 影响）${NC}"
    fi
done

if $HAS_V6; then
    ip6tables -A INPUT -p icmpv6 -j ACCEPT
    ip6tables -A INPUT -s fe80::/10 -d fe80::/10 -p udp --dport 546 -j ACCEPT
fi

# ------------------------------------------------------------
# 4. DDoS 限速规则（使用子链，必须在端口放行规则之前！）
# ------------------------------------------------------------
# ⚠️ 关键设计：DDoS 限速规则必须放在子链中！
# 在主链（如 INPUT）中，RETURN 等同于执行默认策略（DROP），
# 不会继续匹配后续端口 ACCEPT 规则。放在子链中，RETURN 会返回主链继续匹配。
# 正确的匹配流程：
#   保命规则 → 管理子链(et-input等) → DDOS-PROTECT 子链 → 限速RETURN回主链 → 端口ACCEPT → 默认DROP
# 管理子链跳转（如 et-input）在 DDOS-PROTECT 之前，VPN 流量可以绕过限速检查。
if [ "$ENABLE_DDOS_DEFENSE" = "true" ]; then
    echo -e "${GREEN}[4/8] 配置 DDoS 限速规则（SYN Flood / UDP Flood）${NC}"
    for cmd in $(get_active_cmds); do
        # 创建 DDoS 防御子链
        $cmd -N DDOS-PROTECT 2>/dev/null || $cmd -F DDOS-PROTECT

        # TCP SYN 限速：
        # 超限 → DROP（防洪水攻击）
        # 未超限 → RETURN（返回主链继续匹配端口 ACCEPT 规则）
        # ⚠️ 在子链中 RETURN 才会返回主链，在主链中 RETURN 等于执行默认策略 DROP！
        $cmd -A DDOS-PROTECT -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j RETURN
        $cmd -A DDOS-PROTECT -p tcp --syn -j DROP

        # UDP 限速：
        # 超限 → DROP（防洪水攻击）
        # 未超限 → RETURN（返回主链继续匹配端口规则）
        $cmd -A DDOS-PROTECT -p udp -m limit --limit ${DDOS_UDP_RATE}/s -j RETURN
        $cmd -A DDOS-PROTECT -p udp -j DROP

        # 将子链跳转插入到 conntrack 规则之后
        $cmd -A INPUT -j DDOS-PROTECT
    done
    ddos_label=$($HAS_V4 && $HAS_V6 && echo "IPv4+IPv6" || ($HAS_V4 && echo "仅IPv4" || echo "仅IPv6"))
    echo -e "${BLUE}   🛡️  TCP SYN ≤${DDOS_SYN_RATE}/s (burst ${DDOS_SYN_BURST}), UDP ≤${DDOS_UDP_RATE}/s (${ddos_label})${NC}"
else
    echo -e "${YELLOW}   ℹ️  DDoS 防御已禁用（ENABLE_DDOS_DEFENSE=false）${NC}"
fi

# ------------------------------------------------------------
# 5. 双栈放行业务端口
# ------------------------------------------------------------
echo -e "${GREEN}[5/8] 放行 SSH / Web 端口${NC}"
# 注意：Tailscale 端口由 ts-input 子链自动管理，无需手动放行
# 注意：1Panel 端口由 1PANEL_INPUT 子链自动管理，无需手动放行
# 第三方服务（1Panel/Tailscale 等）会在初始化完成后自动注入子链并置顶，不依赖我们的端口规则
for PORT in "${ALL_PORTS[@]}"; do
    $HAS_V4 && iptables -A INPUT -p tcp --dport "$PORT" -j ACCEPT
    $HAS_V6 && ip6tables -A INPUT -p tcp --dport "$PORT" -j ACCEPT
    port_label=$($HAS_V4 && $HAS_V6 && echo "IPv4/IPv6" || ($HAS_V4 && echo "IPv4" || echo "IPv6"))
    echo -e "${BLUE}   ✅ 已放行端口: $PORT (${port_label})${NC}"
done

# ------------------------------------------------------------
# 6. 设置默认 DROP 策略（最后一步设置，确保所有规则已添加）
# ------------------------------------------------------------
echo -e "${GREEN}[6/8] 设置默认安全 DROP 策略${NC}"
# ⚠️ 关键设计：默认策略放在最后设置！
# 这样可以确保在规则重建过程中不会因默认 DROP 导致 SSH 断连
# 执行顺序：先全开放(ACCEPT) → 清空规则 → 添加规则 → 最后设为DROP
iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT
$HAS_V6 && { ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP; ip6tables -P OUTPUT ACCEPT; }

# ------------------------------------------------------------
# 7. Docker 兼容 + 持久化
# ------------------------------------------------------------
echo -e "${GREEN}[7/8] 配置 Docker 网络支持 + 持久化规则${NC}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q "net.ipv4.ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
if $HAS_V6; then
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
    grep -q "net.ipv6.conf.all.forwarding" /etc/sysctl.conf || echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
fi

# ⚠️ DOCKER-USER 链必须在 Docker 自己管控的子链（DOCKER-ISOLATION、DOCKER）之前！
# Docker 的设计意图：DOCKER-USER 是用户自定义过滤 Docker 转发流量的入口点，
# 必须在 DOCKER-ISOLATION 和 DOCKER 链之前执行，否则用户过滤规则无法生效。
# Docker 启动时会自动把 DOCKER-USER 保持在 FORWARD 链最前面。

# 创建 DOCKER-USER 链并插入到 FORWARD 链最前面（早于后续 Docker 自动添加的子链）
# 参考 easytier-firewall.sh 的写法：先 -D 删除旧的跳转引用，再 -I 创建新的
# 仅对实际存在的协议栈操作
for cmd in $(get_active_cmds); do
    $cmd -N DOCKER-USER 2>/dev/null || $cmd -F DOCKER-USER
    $cmd -D FORWARD -j DOCKER-USER 2>/dev/null || true
    $cmd -A DOCKER-USER -j RETURN
    $cmd -I FORWARD -j DOCKER-USER
done

# DDoS 防御（DOCKER-USER 链，保护 Docker 转发流量）
# 先删除旧的 DDoS 规则，再添加新的（-D + -A 模式，避免 iptables -C 的 nft 错误）
if [ "$ENABLE_DDOS_DEFENSE" = "true" ]; then
    # 删除旧版 ACCEPT 规则（兼容历史配置）和当前 RETURN 规则
    # 清理时两栈都尝试（安全清理），但只对存在的栈创建新规则
    for cmd in iptables ip6tables; do
        $cmd -D DOCKER-USER -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j ACCEPT 2>/dev/null || true
        $cmd -D DOCKER-USER -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j RETURN 2>/dev/null || true
        $cmd -D DOCKER-USER -p tcp --syn -j DROP 2>/dev/null || true
        $cmd -D DOCKER-USER -p udp -m limit --limit ${DDOS_UDP_RATE}/s -j RETURN 2>/dev/null || true
        $cmd -D DOCKER-USER -p udp -j DROP 2>/dev/null || true
    done

    # 仅对实际存在的协议栈创建新规则
    for cmd in $(get_active_cmds); do
        # TCP SYN 限速：超限 DROP，未超限 RETURN 回主链继续匹配端口规则
        # DOCKER-USER 本身是子链，RETURN 会返回 FORWARD 链继续匹配
        $cmd -A DOCKER-USER -p tcp --syn -m limit --limit ${DDOS_SYN_RATE}/s --limit-burst ${DDOS_SYN_BURST} -j RETURN
        $cmd -A DOCKER-USER -p tcp --syn -j DROP
        # UDP 限速：超限 DROP，未超限 RETURN
        $cmd -A DOCKER-USER -p udp -m limit --limit ${DDOS_UDP_RATE}/s -j RETURN
        $cmd -A DOCKER-USER -p udp -j DROP
    done
    docker_label=$($HAS_V4 && $HAS_V6 && echo "IPv4+IPv6" || ($HAS_V4 && echo "仅IPv4" || echo "仅IPv6"))
    echo -e "${BLUE}   ✅ DOCKER-USER 链 DDoS 防御已配置（${docker_label}）${NC}"
fi

# Docker 手动转发规则（放行 docker0 桥接流量）
# 这些规则放在 DOCKER-USER 之后，Docker 重启后会自动管理 DOCKER/DOCKER-ISOLATION 链
# Docker 主要使用 IPv4，仅在 IPv4 栈存在时添加
$HAS_V4 && {
    iptables -A FORWARD -i "$DEFAULT_ETH" -o docker0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i docker0 ! -o docker0 -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i docker0 -o docker0 -j ACCEPT 2>/dev/null || true
}

# 持久化
save_rules

systemctl disable --now ufw 2>/dev/null || true
systemctl enable --now netfilter-persistent 2>/dev/null || true

# 重启 Docker 以重建 iptables 链（DOCKER、DOCKER-ISOLATION 等）
# 初始化时 iptables -X 会删除 Docker 自动创建的自定义链，
# 导致后续 docker-compose 创建新 bridge 网络时报错：
#   "No chain/target/match by that name"
# Docker 重启后会自动在 FORWARD 链中插入 DOCKER-ISOLATION 和 DOCKER 子链，
# 并确保 DOCKER-USER 始终保持在最前面（早于 DOCKER-ISOLATION 和 DOCKER）
if systemctl is-enabled --quiet docker 2>/dev/null; then
    echo -e "${BLUE}   🔄 重启 Docker 以重建 iptables 链...${NC}"
    systemctl restart docker 2>/dev/null || true
    # Docker 重启后会在 FORWARD 链中插入 DOCKER-ISOLATION 和 DOCKER 子链，
    # 需要重新持久化以保留 Docker 自动创建的链
    save_rules
    echo -e "${BLUE}   ✅ Docker 已重启，网络链已重建并持久化${NC}"
fi

# Tailscale 规则重建
echo -e "${GREEN}[补充] Tailscale 规则重建与端口配置${NC}"

if [ -f "${TAILSCALE_CONF}" ]; then
    sed -i 's/^PORT=".*"/PORT="'${TAILSCALE_PORT}'"/' "${TAILSCALE_CONF}"
    if ! grep -q '^PORT=' "${TAILSCALE_CONF}"; then
        echo 'PORT="'${TAILSCALE_PORT}'"' >> "${TAILSCALE_CONF}"
    fi
    if ! grep -q '^FLAGS=' "${TAILSCALE_CONF}"; then
        echo 'FLAGS=""' >> "${TAILSCALE_CONF}"
    fi
    systemctl daemon-reload

    if [ "$TAILSCALE_WAS_ACTIVE" = "true" ]; then
        systemctl restart tailscaled 2>/dev/null || true
        echo -e "${BLUE}   ✅ Tailscale 已重启，防火墙规则已重建，端口固定为 ${TAILSCALE_PORT}${NC}"
    else
        systemctl start tailscaled 2>/dev/null || true
        sleep 1
        systemctl stop tailscaled 2>/dev/null || true
        echo -e "${BLUE}   ✅ Tailscale 防火墙规则已重建并恢复停止状态，端口固定为 ${TAILSCALE_PORT}${NC}"
    fi
else
    echo -e "${YELLOW}   ℹ️  ${TAILSCALE_CONF} 不存在，跳过 Tailscale 配置${NC}"
fi

# 第三方服务规则重建
# 1Panel、Tailscale 等第三方服务的防火墙子链在清空规则时会被删除，
# 但它们各自会自动重新注入子链跳转并置顶（1PANEL_INPUT、ts-input 等）。
# 我们只需重启服务让它们重建，不需要手动管理这些子链。
if [ "$PANEL_WAS_ACTIVE" = "true" ]; then
    echo -e "${BLUE}   🔄 重启 1Panel 以重建防火墙规则...${NC}"
    systemctl restart 1panel 2>/dev/null || true
    # 1Panel 重启后会自动将 1PANEL_INPUT 等子链跳转置顶插入到 INPUT 链最前方
    save_rules
    echo -e "${BLUE}   ✅ 1Panel 已重启，子链规则已自动重建并置顶${NC}"
fi

# NetBird 规则重建（NetBird 使用 WireGuard 接口 wt0，不使用子链）
# NetBird 不像 Tailscale/EasyTier 那样创建子链，而是直接在主链中添加规则
# 规则包括：放行 wt0 接口入站流量、转发规则等
if [ "$NETBIRD_WAS_ACTIVE" = "true" ]; then
    echo -e "${BLUE}   🔄 重启 NetBird 以重建防火墙规则...${NC}"
    systemctl restart netbird 2>/dev/null || true
    # NetBird 重启后会自动在主链中添加 wt0 相关规则
    sleep 2
    save_rules
    echo -e "${BLUE}   ✅ NetBird 已重启，防火墙规则已重建（wt0 接口）${NC}"
fi

# ------------------------------------------------------------
# 8. 部署防火墙管理工具
# ------------------------------------------------------------
echo -e "${GREEN}[8/8] 部署防火墙管理工具${NC}"

# 部署自身到 /usr/local/bin/setfirewall
cp "$0" /usr/local/bin/setfirewall
chmod +x /usr/local/bin/setfirewall
echo -e "${BLUE}   ✅ setfirewall 已部署${NC}"

# ------------------------------------------------------------
# 完成提示
# ------------------------------------------------------------
echo -e "\n${GREEN}🎉 初始化完成！${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}⚠️  重要提醒（请务必按顺序执行）：${NC}"
echo ""
echo -e "1️⃣  ${YELLOW}网页控制台放行端口${NC}"
echo "   登录 Oracle Cloud 控制台 → 虚拟云网络(VCN) → 安全列表(Security List)"
echo "   添加入站规则，放行 TCP: ${ALL_PORTS[*]}"
echo "   UDP: ${TAILSCALE_PORT} (Tailscale) 由 ts-input 子链自动管理，无需手动添加"
echo ""
echo -e "2️⃣ ${YELLOW}可选：安装管理面板（如 1Panel 等）${NC}"
echo "   1Panel 安装: bash -c \"\$(curl -fsSL https://resource.fit2cloud.com/1panel/package/v2/quick_start.sh)\""
echo "   安装后面板会自动注入防火墙子链并置顶"
echo "   如果面板端口已自动检测，会一并放行"
echo ""
echo -e "3️⃣ ${YELLOW}后续防火墙管理${NC}"
echo "   直接输入 ${GREEN}setfirewall${NC} 打开管理菜单"
echo "   或命令行操作: ${GREEN}setfirewall open 8080${NC} / ${GREEN}setfirewall allow 1.2.3.4${NC}"
echo "   启用 DDoS 防御: ${GREEN}setfirewall ddos-on${NC}（默认关闭，按需手动开启）"
echo "   管控 Docker 容器: ${GREEN}setfirewall docker-block-port 3306${NC}（封锁外部访问容器端口）"
echo ""
echo -e "${GREEN}当前状态：系统级防火墙已锁定，Docker 已兼容，管理工具已就绪。${NC}"
