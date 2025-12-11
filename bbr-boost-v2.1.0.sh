#!/bin/bash
#
# BBR Boost - TCP BBR 拥塞控制加速脚本 (生产版)
# 支持: Ubuntu 24+ / Debian 12+
# 功能: 智能检测、一键启用、代理场景优化
# 版本: 2.1.0
#

# ==================== 颜色定义 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m'

# ==================== 全局变量 ====================
SYSCTL_CONF="/etc/sysctl.d/99-bbr-boost.conf"
BACKUP_DIR="/var/backups/bbr-boost"
LOG_FILE="/var/log/bbr-boost.log"
LOCK_FILE="/var/run/bbr-boost.lock"
SCRIPT_VERSION="2.1.0"
MIN_KERNEL_VERSION="4.9"
MAX_LOG_SIZE=$((5 * 1024 * 1024))  # 5MB
DRY_RUN=false
QUIET=false

# ==================== 信号处理与清理 ====================

cleanup() {
    rm -f "$LOCK_FILE" 2>/dev/null
    log DEBUG "清理完成"
}

trap cleanup EXIT
trap 'log WARN "收到中断信号"; exit 130' INT TERM

# 获取文件锁，防止多实例运行
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid=$(cat "$LOCK_FILE" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log ERROR "另一个实例正在运行 (PID: $pid)"
            exit 1
        fi
        # 旧锁文件，进程已不存在，移除它
        rm -f "$LOCK_FILE"
    fi
    echo $$ > "$LOCK_FILE"
}

# ==================== 日志函数 ====================

rotate_log() {
    if [[ -f "$LOG_FILE" ]]; then
        local size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ $size -gt $MAX_LOG_SIZE ]]; then
            mv "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null
            touch "$LOG_FILE"
        fi
    fi
}

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 写入日志文件
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    
    # 控制台输出
    if [[ "$QUIET" != true ]]; then
        case "$level" in
            INFO)  echo -e "${BLUE}[INFO]${NC} $message" ;;
            OK)    echo -e "${GREEN}[✓]${NC} $message" ;;
            WARN)  echo -e "${YELLOW}[!]${NC} $message" ;;
            ERROR) echo -e "${RED}[✗]${NC} $message" ;;
            DEBUG) [[ "${DEBUG:-}" == true ]] && echo -e "${CYAN}[DEBUG]${NC} $message" ;;
        esac
    fi
}

print_header() {
    [[ "$QUIET" == true ]] && return
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║          BBR Boost - TCP 加速脚本 v${SCRIPT_VERSION} (生产版)         ║"
    echo "║            支持 Ubuntu 24+ / Debian 12+ 智能检测          ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_separator() {
    [[ "$QUIET" == true ]] && return
    echo -e "${BLUE}────────────────────────────────────────────────────────────────${NC}"
}

# ==================== 初始化 ====================

init_environment() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    mkdir -p "$BACKUP_DIR" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || true
    
    rotate_log
    
    log INFO "=== BBR Boost v${SCRIPT_VERSION} 启动 ==="
    log INFO "运行用户: $(whoami), PID: $$"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "此脚本需要 root 权限运行"
        echo "请使用: sudo $0" >&2
        exit 1
    fi
}

# ==================== 系统检测 ====================

get_os_info() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME="${NAME:-Unknown}"
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-0}"
        OS_PRETTY="${PRETTY_NAME:-Unknown OS}"
    else
        OS_NAME="Unknown"
        OS_ID="unknown"
        OS_VERSION="0"
        OS_PRETTY="Unknown OS"
    fi
}

get_kernel_info() {
    KERNEL_VERSION=$(uname -r)
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2 | cut -d- -f1)
    # 确保是数字
    KERNEL_MAJOR=${KERNEL_MAJOR//[!0-9]/}
    KERNEL_MINOR=${KERNEL_MINOR//[!0-9]/}
    KERNEL_MAJOR=${KERNEL_MAJOR:-0}
    KERNEL_MINOR=${KERNEL_MINOR:-0}
    KERNEL_FULL="${KERNEL_MAJOR}.${KERNEL_MINOR}"
}

get_system_memory() {
    local mem_kb
    mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null)
    if [[ -n "$mem_kb" && "$mem_kb" =~ ^[0-9]+$ ]]; then
        echo $((mem_kb / 1024))
    else
        echo "0"
    fi
}

# 版本比较 - 修复单数字版本号问题
version_ge() {
    local v1="$1"
    local v2="$2"
    
    # 提取主版本号
    local v1_major="${v1%%.*}"
    local v2_major="${v2%%.*}"
    
    # 提取次版本号（如果有）
    local v1_minor="0"
    local v2_minor="0"
    
    if [[ "$v1" == *.* ]]; then
        v1_minor="${v1#*.}"
        v1_minor="${v1_minor%%.*}"
    fi
    
    if [[ "$v2" == *.* ]]; then
        v2_minor="${v2#*.}"
        v2_minor="${v2_minor%%.*}"
    fi
    
    # 清理非数字字符
    v1_major=${v1_major//[!0-9]/}
    v1_minor=${v1_minor//[!0-9]/}
    v2_major=${v2_major//[!0-9]/}
    v2_minor=${v2_minor//[!0-9]/}
    
    # 设置默认值
    v1_major=${v1_major:-0}
    v1_minor=${v1_minor:-0}
    v2_major=${v2_major:-0}
    v2_minor=${v2_minor:-0}
    
    if [[ $v1_major -gt $v2_major ]]; then
        return 0
    elif [[ $v1_major -eq $v2_major && $v1_minor -ge $v2_minor ]]; then
        return 0
    fi
    return 1
}

check_system_compatibility() {
    get_os_info
    
    case "$OS_ID" in
        ubuntu)
            if version_ge "${OS_VERSION}" "24"; then
                echo "compatible"
            else
                echo "需要 Ubuntu 24.04+ (当前: $OS_VERSION)"
            fi
            ;;
        debian)
            if version_ge "${OS_VERSION}" "12"; then
                echo "compatible"
            else
                echo "需要 Debian 12+ (当前: $OS_VERSION)"
            fi
            ;;
        *)
            echo "不支持的系统: $OS_NAME ($OS_ID)"
            ;;
    esac
}

check_kernel_support() {
    get_kernel_info
    
    if version_ge "$KERNEL_FULL" "$MIN_KERNEL_VERSION"; then
        echo "supported"
    else
        echo "内核版本过低: $KERNEL_VERSION (需要 >= $MIN_KERNEL_VERSION)"
    fi
}

check_bbr_module() {
    if grep -q "tcp_bbr" /proc/modules 2>/dev/null; then
        echo "loaded"
    elif modprobe -n tcp_bbr 2>/dev/null; then
        echo "available"
    else
        echo "unavailable"
    fi
}

get_current_congestion() {
    sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown"
}

get_available_congestion() {
    sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "unknown"
}

get_current_qdisc() {
    sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown"
}

is_bbr_enabled() {
    local current=$(get_current_congestion)
    local qdisc=$(get_current_qdisc)
    
    if [[ "$current" == "bbr" && "$qdisc" == "fq" ]]; then
        echo "full"
    elif [[ "$current" == "bbr" ]]; then
        echo "partial"
    else
        echo "disabled"
    fi
}

check_persistence() {
    if [[ -f "$SYSCTL_CONF" ]]; then
        if grep -q "tcp_congestion_control.*bbr" "$SYSCTL_CONF" 2>/dev/null; then
            echo "configured"
        else
            echo "incomplete"
        fi
    elif grep -q "tcp_congestion_control.*bbr" /etc/sysctl.conf 2>/dev/null; then
        echo "legacy"
    else
        echo "none"
    fi
}

check_sysctl_param() {
    sysctl "$1" >/dev/null 2>&1
}

# ==================== 备份与恢复 ====================

create_backup() {
    local backup_file="${BACKUP_DIR}/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    local temp_dir
    temp_dir=$(mktemp -d) || { log ERROR "无法创建临时目录"; return 1; }
    
    log INFO "创建系统备份..."
    
    # 备份当前 sysctl 值（使用自定义格式便于恢复）
    sysctl -a 2>/dev/null | grep -E "^net\.(core|ipv4)" | while IFS= read -r line; do
        # 格式: key = value -> key=value
        echo "$line" | sed 's/ = /=/'
    done > "${temp_dir}/sysctl_current.conf"
    
    # 备份配置文件
    [[ -f "$SYSCTL_CONF" ]] && cp "$SYSCTL_CONF" "${temp_dir}/" 2>/dev/null
    [[ -f /etc/modules-load.d/bbr.conf ]] && cp /etc/modules-load.d/bbr.conf "${temp_dir}/" 2>/dev/null
    
    # 记录系统信息
    cat > "${temp_dir}/system_info.txt" << EOF
Backup Time: $(date)
OS: ${OS_PRETTY:-Unknown}
Kernel: ${KERNEL_VERSION:-Unknown}
BBR Status: $(is_bbr_enabled)
Congestion: $(get_current_congestion)
Qdisc: $(get_current_qdisc)
Script Version: $SCRIPT_VERSION
EOF
    
    # 创建压缩包
    if tar -czf "$backup_file" -C "$temp_dir" . 2>/dev/null; then
        log OK "备份已创建: $backup_file"
        echo "$backup_file"
    else
        log ERROR "备份创建失败"
        rm -rf "$temp_dir"
        return 1
    fi
    
    rm -rf "$temp_dir"
    
    # 清理旧备份（保留最近 10 个）
    local backup_count
    backup_count=$(find "$BACKUP_DIR" -name "backup_*.tar.gz" -type f 2>/dev/null | wc -l)
    if [[ $backup_count -gt 10 ]]; then
        find "$BACKUP_DIR" -name "backup_*.tar.gz" -type f -printf '%T@ %p\n' 2>/dev/null | \
            sort -n | head -n $((backup_count - 10)) | cut -d' ' -f2- | xargs rm -f 2>/dev/null
        log DEBUG "已清理旧备份"
    fi
}

list_backups() {
    local count
    count=$(find "$BACKUP_DIR" -name "backup_*.tar.gz" -type f 2>/dev/null | wc -l)
    
    if [[ $count -gt 0 ]]; then
        find "$BACKUP_DIR" -name "backup_*.tar.gz" -type f -printf '%T@ %p\n' 2>/dev/null | \
            sort -rn | head -10 | cut -d' ' -f2-
    else
        echo "无备份文件"
    fi
}

get_backup_count() {
    find "$BACKUP_DIR" -name "backup_*.tar.gz" -type f 2>/dev/null | wc -l
}

restore_backup() {
    local backup_file="$1"
    
    if [[ ! -f "$backup_file" ]]; then
        log ERROR "备份文件不存在: $backup_file"
        return 1
    fi
    
    local temp_dir
    temp_dir=$(mktemp -d) || { log ERROR "无法创建临时目录"; return 1; }
    
    if ! tar -xzf "$backup_file" -C "$temp_dir" 2>/dev/null; then
        log ERROR "备份解压失败"
        rm -rf "$temp_dir"
        return 1
    fi
    
    if [[ -f "${temp_dir}/sysctl_current.conf" ]]; then
        log INFO "恢复 sysctl 参数..."
        local restored=0
        local failed=0
        
        while IFS='=' read -r key value; do
            # 跳过空行
            [[ -z "$key" ]] && continue
            
            # 清理空白字符
            key=$(echo "$key" | tr -d '[:space:]')
            value=$(echo "$value" | xargs 2>/dev/null || echo "$value")
            
            if [[ -n "$key" && -n "$value" ]]; then
                if sysctl -w "${key}=${value}" >/dev/null 2>&1; then
                    ((restored++))
                else
                    ((failed++))
                fi
            fi
        done < "${temp_dir}/sysctl_current.conf"
        
        log OK "恢复完成: 成功 $restored 项, 失败 $failed 项"
    fi
    
    rm -rf "$temp_dir"
}

# ==================== 配置生成 ====================

calculate_buffer_sizes() {
    local mem_mb
    mem_mb=$(get_system_memory)
    
    # 确保 mem_mb 是有效数字
    if [[ ! "$mem_mb" =~ ^[0-9]+$ ]] || [[ $mem_mb -eq 0 ]]; then
        mem_mb=1024  # 默认假设 1GB
        log WARN "无法获取内存大小，使用默认值"
    fi
    
    if [[ $mem_mb -lt 1024 ]]; then
        # < 1GB: 保守配置
        RMEM_MAX=4194304
        WMEM_MAX=4194304
        TCP_RMEM="4096 65536 4194304"
        TCP_WMEM="4096 16384 4194304"
        TCP_MEM="32768 65536 131072"
    elif [[ $mem_mb -lt 4096 ]]; then
        # 1-4GB: 中等配置
        RMEM_MAX=8388608
        WMEM_MAX=8388608
        TCP_RMEM="4096 131072 8388608"
        TCP_WMEM="4096 16384 8388608"
        TCP_MEM="65536 131072 262144"
    else
        # >= 4GB: 高性能配置
        RMEM_MAX=16777216
        WMEM_MAX=16777216
        TCP_RMEM="4096 131072 16777216"
        TCP_WMEM="4096 16384 16777216"
        TCP_MEM="262144 524288 1048576"
    fi
    
    log DEBUG "内存: ${mem_mb}MB, RMEM_MAX=${RMEM_MAX}"
}

generate_bbr_config() {
    calculate_buffer_sizes
    
    cat << EOF
# ============================================================
# BBR Boost - TCP 优化配置 (生产版 v${SCRIPT_VERSION})
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 系统内存: $(get_system_memory) MB
# 适用场景: 代理服务器 / 高延迟网络优化
# ============================================================

# -------------------- BBR 核心配置 --------------------
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# -------------------- 缓冲区优化 --------------------
net.core.rmem_default = 1048576
net.core.rmem_max = ${RMEM_MAX}
net.core.wmem_default = 1048576
net.core.wmem_max = ${WMEM_MAX}
net.ipv4.tcp_rmem = ${TCP_RMEM}
net.ipv4.tcp_wmem = ${TCP_WMEM}
net.ipv4.tcp_mem = ${TCP_MEM}

# -------------------- TCP 连接优化 --------------------
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# -------------------- 连接复用与超时 --------------------
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# -------------------- 端口范围 --------------------
net.ipv4.ip_local_port_range = 1024 65535

# -------------------- 孤儿/TIME-WAIT 限制 --------------------
net.ipv4.tcp_max_orphans = 65535
net.ipv4.tcp_max_tw_buckets = 65535

# -------------------- MTU 探测 --------------------
net.ipv4.tcp_mtu_probing = 1
EOF
}

generate_conntrack_config() {
    cat << 'EOF'
# BBR Boost - Conntrack 优化 (可选)
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
EOF
}

# ==================== 应用配置 ====================

apply_sysctl_safely() {
    local config_file="$1"
    local errors=0
    local applied=0
    local skipped=0
    
    log INFO "安全应用 sysctl 配置..."
    
    while IFS= read -r line; do
        # 跳过注释和空行
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        
        # 解析参数（支持 key = value 和 key=value 两种格式）
        local param value
        param=$(echo "$line" | cut -d= -f1 | xargs)
        value=$(echo "$line" | cut -d= -f2- | xargs)
        
        [[ -z "$param" ]] && continue
        
        if [[ "$DRY_RUN" == true ]]; then
            echo "[DRY-RUN] sysctl -w ${param}=${value}"
            continue
        fi
        
        if check_sysctl_param "$param"; then
            if sysctl -w "${param}=${value}" >/dev/null 2>&1; then
                ((applied++))
                log DEBUG "已应用: ${param}=${value}"
            else
                ((errors++))
                log WARN "应用失败: ${param}"
            fi
        else
            ((skipped++))
            log DEBUG "参数不存在，跳过: ${param}"
        fi
    done < "$config_file"
    
    log INFO "配置应用完成: 成功 $applied, 失败 $errors, 跳过 $skipped"
    return 0
}

load_bbr_module() {
    log INFO "加载 BBR 模块..."
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY-RUN] modprobe tcp_bbr"
        return 0
    fi
    
    if ! modprobe tcp_bbr 2>/dev/null; then
        log ERROR "无法加载 BBR 模块"
        return 1
    fi
    
    # 持久化模块加载
    mkdir -p /etc/modules-load.d 2>/dev/null
    if [[ ! -f /etc/modules-load.d/bbr.conf ]]; then
        echo "tcp_bbr" > /etc/modules-load.d/bbr.conf
    fi
    
    log OK "BBR 模块已加载"
    return 0
}

apply_bbr_config() {
    # 创建备份
    create_backup || log WARN "备份创建失败，继续执行..."
    
    log INFO "生成 BBR 配置..."
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY-RUN] 将生成配置:"
        generate_bbr_config
        return 0
    fi
    
    generate_bbr_config > "$SYSCTL_CONF"
    log OK "配置文件已生成: $SYSCTL_CONF"
    
    apply_sysctl_safely "$SYSCTL_CONF"
    
    # 尝试应用 conntrack 配置
    if check_sysctl_param "net.netfilter.nf_conntrack_max"; then
        log INFO "检测到 conntrack 模块，应用优化..."
        local conntrack_conf="/etc/sysctl.d/99-bbr-conntrack.conf"
        generate_conntrack_config > "$conntrack_conf"
        apply_sysctl_safely "$conntrack_conf"
    else
        log INFO "conntrack 模块未加载，跳过相关优化"
    fi
    
    log OK "配置应用完成"
    return 0
}

quick_enable_bbr() {
    log INFO "快速启用 BBR (临时)..."
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY-RUN] sysctl -w net.core.default_qdisc=fq"
        echo "[DRY-RUN] sysctl -w net.ipv4.tcp_congestion_control=bbr"
        return 0
    fi
    
    modprobe tcp_bbr 2>/dev/null || true
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1
    
    if [[ $(get_current_congestion) == "bbr" ]]; then
        log OK "BBR 已临时启用 (重启后失效)"
        return 0
    else
        log ERROR "BBR 启用失败"
        return 1
    fi
}

disable_bbr() {
    log INFO "禁用 BBR..."
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY-RUN] 将禁用 BBR 并删除配置"
        return 0
    fi
    
    # 创建备份
    create_backup || true
    
    local default_qdisc="fq_codel"
    
    sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1
    sysctl -w net.core.default_qdisc="$default_qdisc" >/dev/null 2>&1
    
    rm -f "$SYSCTL_CONF" /etc/sysctl.d/99-bbr-conntrack.conf 2>/dev/null
    rm -f /etc/modules-load.d/bbr.conf 2>/dev/null
    
    log OK "BBR 已禁用，切换回 cubic + $default_qdisc"
}

# ==================== 状态显示 ====================

show_status() {
    print_header
    echo -e "${BOLD}${WHITE}【系统状态检测】${NC}"
    print_separator
    
    get_os_info
    get_kernel_info
    
    echo -e "${CYAN}▸ 系统信息${NC}"
    echo -e "  操作系统: ${WHITE}$OS_PRETTY${NC}"
    echo -e "  系统内存: ${WHITE}$(get_system_memory) MB${NC}"
    
    local compat=$(check_system_compatibility)
    if [[ "$compat" == "compatible" ]]; then
        echo -e "  兼容状态: ${GREEN}✓ 兼容${NC}"
    else
        echo -e "  兼容状态: ${RED}✗ $compat${NC}"
    fi
    echo ""
    
    echo -e "${CYAN}▸ 内核信息${NC}"
    echo -e "  内核版本: ${WHITE}$KERNEL_VERSION${NC}"
    
    local kernel_support=$(check_kernel_support)
    if [[ "$kernel_support" == "supported" ]]; then
        echo -e "  BBR 支持: ${GREEN}✓ 支持${NC}"
    else
        echo -e "  BBR 支持: ${RED}✗ $kernel_support${NC}"
    fi
    
    local bbr_module=$(check_bbr_module)
    case "$bbr_module" in
        loaded)    echo -e "  BBR 模块: ${GREEN}✓ 已加载${NC}" ;;
        available) echo -e "  BBR 模块: ${YELLOW}○ 可用未加载${NC}" ;;
        *)         echo -e "  BBR 模块: ${RED}✗ 不可用${NC}" ;;
    esac
    echo ""
    
    echo -e "${CYAN}▸ BBR 状态${NC}"
    echo -e "  拥塞控制: ${WHITE}$(get_current_congestion)${NC}"
    echo -e "  队列调度: ${WHITE}$(get_current_qdisc)${NC}"
    echo -e "  可用算法: ${WHITE}$(get_available_congestion)${NC}"
    
    local bbr_status=$(is_bbr_enabled)
    case "$bbr_status" in
        full)     echo -e "  BBR 加速: ${GREEN}✓ 完全启用 (BBR + fq)${NC}" ;;
        partial)  echo -e "  BBR 加速: ${YELLOW}○ 部分启用${NC}" ;;
        disabled) echo -e "  BBR 加速: ${RED}✗ 未启用${NC}" ;;
    esac
    echo ""
    
    echo -e "${CYAN}▸ 持久化配置${NC}"
    local persist=$(check_persistence)
    case "$persist" in
        configured) echo -e "  状态: ${GREEN}✓ 已持久化 ($SYSCTL_CONF)${NC}" ;;
        legacy)     echo -e "  状态: ${YELLOW}○ 旧式配置 (/etc/sysctl.conf)${NC}" ;;
        *)          echo -e "  状态: ${RED}✗ 未持久化${NC}" ;;
    esac
    
    echo -e "  备份数量: ${WHITE}$(get_backup_count)${NC}"
    
    print_separator
}

# ==================== 一键自动模式 ====================

auto_mode() {
    local exit_code=0
    
    print_header
    echo -e "${BOLD}${WHITE}【一键自动模式】${NC}"
    print_separator
    echo ""
    
    if [[ "$DRY_RUN" == true ]]; then
        echo -e "${YELLOW}*** DRY-RUN 模式: 仅预览，不实际执行 ***${NC}"
        echo ""
    fi
    
    echo -e "${CYAN}[1/5] 检查系统兼容性...${NC}"
    local compat=$(check_system_compatibility)
    if [[ "$compat" != "compatible" ]]; then
        log ERROR "系统不兼容: $compat"
        return 1
    fi
    log OK "系统兼容: $OS_PRETTY"
    
    echo -e "${CYAN}[2/5] 检查内核支持...${NC}"
    local kernel_support=$(check_kernel_support)
    if [[ "$kernel_support" != "supported" ]]; then
        log ERROR "$kernel_support"
        return 1
    fi
    log OK "内核支持: $KERNEL_VERSION"
    
    echo -e "${CYAN}[3/5] 加载 BBR 模块...${NC}"
    if ! load_bbr_module; then
        return 1
    fi
    
    echo -e "${CYAN}[4/5] 应用 BBR 配置与优化...${NC}"
    if ! apply_bbr_config; then
        return 1
    fi
    
    echo -e "${CYAN}[5/5] 验证配置结果...${NC}"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        echo -e "${YELLOW}*** DRY-RUN 完成，未实际更改系统 ***${NC}"
        return 0
    fi
    
    sleep 1
    local final_status=$(is_bbr_enabled)
    
    if [[ "$final_status" == "full" ]]; then
        echo ""
        print_separator
        echo -e "${GREEN}${BOLD}"
        echo "  ╔════════════════════════════════════════╗"
        echo "  ║     ✓ BBR 加速已成功启用并持久化!     ║"
        echo "  ╚════════════════════════════════════════╝"
        echo -e "${NC}"
        echo -e "  拥塞控制: ${GREEN}bbr${NC}"
        echo -e "  队列调度: ${GREEN}fq${NC}"
        echo -e "  持久化:   ${GREEN}重启后自动生效${NC}"
        print_separator
        return 0
    else
        log ERROR "配置验证失败"
        return 1
    fi
}

# ==================== 菜单系统 ====================

show_menu() {
    print_header
    
    local bbr_status=$(is_bbr_enabled)
    local persist=$(check_persistence)
    
    echo -e "${WHITE}当前状态:${NC}"
    case "$bbr_status" in
        full)     echo -e "  BBR: ${GREEN}● 已启用${NC} | 持久化: $([ "$persist" == "configured" ] && echo "${GREEN}● 是${NC}" || echo "${YELLOW}○ 否${NC}")" ;;
        partial)  echo -e "  BBR: ${YELLOW}◐ 部分启用${NC} | 持久化: $([ "$persist" == "configured" ] && echo "${GREEN}● 是${NC}" || echo "${YELLOW}○ 否${NC}")" ;;
        disabled) echo -e "  BBR: ${RED}○ 未启用${NC} | 持久化: ${RED}○ 否${NC}" ;;
    esac
    echo ""
    
    print_separator
    echo -e "${BOLD}${WHITE}请选择操作:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} 🚀 一键自动模式 ${CYAN}(推荐)${NC}"
    echo -e "  ${GREEN}2)${NC} 📊 查看详细状态"
    echo -e "  ${GREEN}3)${NC} ⚡ 快速启用 BBR (临时)"
    echo -e "  ${GREEN}4)${NC} 🔧 启用 BBR + 优化 (持久化)"
    echo -e "  ${GREEN}5)${NC} ❌ 禁用 BBR"
    echo -e "  ${GREEN}6)${NC} 📄 查看配置文件"
    echo -e "  ${GREEN}7)${NC} 🔄 列出/恢复备份"
    echo -e "  ${GREEN}8)${NC} 🧪 Dry-Run 预览"
    echo -e "  ${GREEN}0)${NC} 退出"
    echo ""
    print_separator
}

view_config() {
    print_header
    echo -e "${BOLD}${WHITE}【配置文件内容】${NC}"
    print_separator
    
    if [[ -f "$SYSCTL_CONF" ]]; then
        echo -e "${CYAN}文件: $SYSCTL_CONF${NC}"
        echo ""
        cat "$SYSCTL_CONF"
    else
        log WARN "配置文件不存在"
    fi
    print_separator
}

backup_menu() {
    print_header
    echo -e "${BOLD}${WHITE}【备份管理】${NC}"
    print_separator
    
    echo -e "${CYAN}现有备份 (最近 10 个):${NC}"
    echo ""
    list_backups
    echo ""
    
    echo -e "输入备份文件完整路径进行恢复，或按 Enter 返回:"
    read -r backup_path
    
    if [[ -n "$backup_path" ]]; then
        restore_backup "$backup_path"
    fi
}

main_menu() {
    while true; do
        show_menu
        
        echo -ne "${BOLD}请输入选项 [0-8]: ${NC}"
        read -r choice
        
        case "$choice" in
            1) auto_mode; echo ""; read -rp "按 Enter 返回..." ;;
            2) show_status; echo ""; read -rp "按 Enter 返回..." ;;
            3) quick_enable_bbr; echo ""; read -rp "按 Enter 返回..." ;;
            4) load_bbr_module; apply_bbr_config; echo ""; read -rp "按 Enter 返回..." ;;
            5)
                echo -ne "${YELLOW}确认禁用 BBR? [y/N]: ${NC}"
                read -r confirm
                [[ "$confirm" =~ ^[Yy]$ ]] && disable_bbr
                echo ""; read -rp "按 Enter 返回..."
                ;;
            6) view_config; echo ""; read -rp "按 Enter 返回..." ;;
            7) backup_menu; echo ""; read -rp "按 Enter 返回..." ;;
            8)
                DRY_RUN=true
                auto_mode
                DRY_RUN=false
                echo ""; read -rp "按 Enter 返回..."
                ;;
            0|q|Q) log INFO "退出"; exit 0 ;;
            *) log ERROR "无效选项"; sleep 1 ;;
        esac
    done
}

# ==================== 命令行参数 ====================

show_help() {
    cat << EOF
BBR Boost v${SCRIPT_VERSION} - TCP BBR 拥塞控制加速脚本 (生产版)

用法: $0 [选项]

选项:
  (无参数)       启动交互式菜单
  --auto         一键自动模式
  --status       显示当前状态
  --enable       快速启用 BBR (临时)
  --disable      禁用 BBR
  --dry-run      预览模式 (不实际更改)
  --quiet        静默模式 (仅输出结果)
  --debug        显示调试信息
  --help         显示帮助

示例:
  sudo $0                    # 交互式菜单
  sudo $0 --auto             # 一键启用
  sudo $0 --dry-run --auto   # 预览一键启用
  sudo $0 --quiet --auto     # 静默一键启用 (适合自动化)
  sudo $0 --status           # 查看状态

日志文件: $LOG_FILE
配置文件: $SYSCTL_CONF
备份目录: $BACKUP_DIR
EOF
}

# ==================== 主入口 ====================

main() {
    # 解析全局选项
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=true; shift ;;
            --quiet|-q) QUIET=true; shift ;;
            --debug) DEBUG=true; shift ;;
            *) break ;;
        esac
    done
    
    check_root
    init_environment
    acquire_lock
    
    local exit_code=0
    
    case "${1:-}" in
        --auto|-a)    auto_mode; exit_code=$? ;;
        --status|-s)  show_status ;;
        --enable|-e)  quick_enable_bbr; exit_code=$? ;;
        --disable|-d) disable_bbr ;;
        --help|-h)    show_help ;;
        "")           main_menu ;;
        *)            log ERROR "未知选项: $1"; show_help; exit_code=1 ;;
    esac
    
    exit $exit_code
}

main "$@"
