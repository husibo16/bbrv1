#!/bin/bash
#
# BBR Boost - TCP tuning script (Production)
# Supports: Ubuntu 24+ / Debian 12+
# Version: 2.4.1 - Enhanced Intelligence (Fixed)
#
# 智能判断增强版：
# - 多维度评估（RTT、带宽利用率、丢包模式、网络环境）
# - 打分制决策（非简单二选一）
# - 云环境/虚拟化检测
# - 代理场景识别
#

set -o pipefail

# ==================== 【颜色定义】 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m'

# ==================== 【全局变量】 ====================
SCRIPT_VERSION="2.4.1"
MIN_KERNEL_VERSION="4.9"

SYSCTL_BBR_CONF="/etc/sysctl.d/99-bbr-boost.conf"
SYSCTL_STABLE_CONF="/etc/sysctl.d/99-proxy-stable.conf"
CONNTRACK_CONF="/etc/sysctl.d/99-bbr-conntrack.conf"
MODULES_BBR_CONF="/etc/modules-load.d/bbr.conf"

BACKUP_DIR="/var/backups/bbr-boost"
LOG_FILE="/var/log/bbr-boost.log"
LOCK_FILE="/var/run/bbr-boost.lock"
MAX_LOG_SIZE=$((5 * 1024 * 1024))  # 5MB

DRY_RUN=false
QUIET=false
DEBUG=false

# Intelligent checks (tunable)
SAMPLE_CONN=100
MSS_SMALL_CUTOFF=1200

ENABLE_ROLLBACK=true

# ==================== 【智能评分系统】 ====================
# 评分范围: -100 到 +100
# 正分倾向 BBR，负分倾向 CUBIC
SCORE_BBR=0
declare -a SCORE_REASONS=()

# 全局结果变量（初始化）
CHOSEN_PROFILE="stable"
CHOOSE_REASON=""
ENV_VIRT="unknown"
ENV_CLOUD="unknown"
RTT_AVG="0"
RTT_MAX="0"
LOSS_RETRANS_PCT=0
LOSS_REORDER_PCT=0
LOSS_SMALLMSS_PCT=0
BW_AVG_CWND="0"
PROXY_DETECTED=0
CONN_COUNT=0
NET_IFACE=""
NET_SPEED=0

# ==================== 【工具函数】 ====================
# 安全地将字符串转为整数
safe_int() {
  local val="$1"
  local default="${2:-0}"
  # 移除小数部分，只保留数字和负号
  val="${val%%.*}"
  val=$(echo "$val" | tr -cd '0-9-')
  # 移除多余的负号（只保留开头的）
  if [[ "$val" == -* ]]; then
    val="-${val//-/}"
  fi
  # 如果为空，返回默认值
  [[ -z "$val" || "$val" == "-" ]] && echo "$default" || echo "$val"
}

# 安全的除法（防止除零）
safe_div() {
  local num="$1"
  local den="$2"
  local default="${3:-0}"
  num=$(safe_int "$num" 0)
  den=$(safe_int "$den" 0)
  if [[ $den -eq 0 ]]; then
    echo "$default"
  else
    echo $((num / den))
  fi
}

# 安全的百分比计算
safe_pct() {
  local num="$1"
  local den="$2"
  num=$(safe_int "$num" 0)
  den=$(safe_int "$den" 0)
  if [[ $den -eq 0 ]]; then
    echo "0"
  else
    echo $((num * 100 / den))
  fi
}

# ==================== 【信号处理与清理】 ====================
cleanup() {
  rm -f "$LOCK_FILE" 2>/dev/null
  log "DEBUG" "清理完成"
}
trap cleanup EXIT
trap 'log "WARN" "收到中断信号"; exit 130' INT TERM

# ==================== 【日志系统】 ====================
rotate_log() {
  if [[ -f "$LOG_FILE" ]]; then
    local size
    size=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)
    size=$(safe_int "$size" 0)
    if [[ $size -gt $MAX_LOG_SIZE ]]; then
      mv "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
      : > "$LOG_FILE" 2>/dev/null || true
    fi
  fi
}

log() {
  local level="$1"
  local message_zh="$2"
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')

  echo "[$ts] [$level] $message_zh" >> "$LOG_FILE" 2>/dev/null || true

  [[ "$QUIET" == true ]] && return 0

  case "$level" in
    INFO)  echo -e "${BLUE}[信息]${NC} $message_zh" ;;
    OK)    echo -e "${GREEN}[成功]${NC} $message_zh" ;;
    WARN)  echo -e "${YELLOW}[警告]${NC} $message_zh" ;;
    ERROR) echo -e "${RED}[错误]${NC} $message_zh" ;;
    DEBUG) [[ "$DEBUG" == true ]] && echo -e "${CYAN}[调试]${NC} $message_zh" ;;
    SCORE) echo -e "${CYAN}[评分]${NC} $message_zh" ;;
    *)     echo -e "${WHITE}[日志]${NC} $message_zh" ;;
  esac
}

print_header() {
  [[ "$QUIET" == true ]] && return
  clear 2>/dev/null || true
  echo -e "${CYAN}${BOLD}"
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║       BBR Boost - TCP tuning script v${SCRIPT_VERSION}             ║"
  echo "║       智能增强版 - 多维度评估 + 打分制决策                 ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

print_separator() {
  [[ "$QUIET" == true ]] && return
  echo -e "${BLUE}────────────────────────────────────────────────────────────────${NC}"
}

# ==================== 【锁与初始化】 ====================
acquire_lock() {
  if [[ -f "$LOCK_FILE" ]]; then
    local pid
    pid=$(cat "$LOCK_FILE" 2>/dev/null || true)
    pid=$(safe_int "$pid" 0)
    if [[ $pid -gt 0 ]] && kill -0 "$pid" 2>/dev/null; then
      log "ERROR" "另一个实例正在运行 (PID: $pid)"
      exit 1
    fi
    rm -f "$LOCK_FILE" 2>/dev/null || true
  fi
  echo $$ > "$LOCK_FILE"
}

check_root() {
  if [[ $EUID -ne 0 ]]; then
    log "ERROR" "需要 root 权限运行"
    echo -e "${YELLOW}提示：${NC}请使用 sudo 运行" >&2
    exit 1
  fi
}

init_environment() {
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  touch "$LOG_FILE" 2>/dev/null || true
  rotate_log
  log "INFO" "脚本启动"
}

# ==================== 【系统信息与版本比较】 ====================
get_os_info() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-0}"
    OS_PRETTY="${PRETTY_NAME:-Unknown OS}"
  else
    OS_ID="unknown"
    OS_VERSION="0"
    OS_PRETTY="Unknown OS"
  fi
}

get_kernel_info() {
  KERNEL_VERSION=$(uname -r)
  local major minor
  major=$(echo "$KERNEL_VERSION" | cut -d. -f1 | tr -cd '0-9')
  minor=$(echo "$KERNEL_VERSION" | cut -d. -f2 | cut -d- -f1 | tr -cd '0-9')
  major=${major:-0}
  minor=${minor:-0}
  KERNEL_FULL="${major}.${minor}"
}

version_ge() {
  local v1="$1" v2="$2"
  local v1_major v1_minor v2_major v2_minor
  v1_major="${v1%%.*}"; v2_major="${v2%%.*}"
  v1_minor="0"; v2_minor="0"
  [[ "$v1" == *.* ]] && v1_minor="${v1#*.}" && v1_minor="${v1_minor%%.*}"
  [[ "$v2" == *.* ]] && v2_minor="${v2#*.}" && v2_minor="${v2_minor%%.*}"

  v1_major=$(safe_int "$v1_major" 0)
  v1_minor=$(safe_int "$v1_minor" 0)
  v2_major=$(safe_int "$v2_major" 0)
  v2_minor=$(safe_int "$v2_minor" 0)

  if [[ $v1_major -gt $v2_major ]]; then return 0; fi
  if [[ $v1_major -eq $v2_major && $v1_minor -ge $v2_minor ]]; then return 0; fi
  return 1
}

check_system_compatibility() {
  get_os_info
  case "$OS_ID" in
    ubuntu)
      version_ge "$OS_VERSION" "24" && return 0
      log "ERROR" "系统不兼容：需要 Ubuntu 24+，当前 $OS_PRETTY"
      return 1
      ;;
    debian)
      version_ge "$OS_VERSION" "12" && return 0
      log "ERROR" "系统不兼容：需要 Debian 12+，当前 $OS_PRETTY"
      return 1
      ;;
    *)
      log "ERROR" "系统不支持：$OS_PRETTY"
      return 1
      ;;
  esac
}

check_kernel_support() {
  get_kernel_info
  if version_ge "$KERNEL_FULL" "$MIN_KERNEL_VERSION"; then
    return 0
  fi
  log "ERROR" "内核版本过低：$KERNEL_VERSION（需要 >= $MIN_KERNEL_VERSION）"
  return 1
}

# ==================== 【读取当前状态】 ====================
get_sysctl_value() {
  local key="$1"
  sysctl -n "$key" 2>/dev/null || echo "unknown"
}

get_current_congestion() { get_sysctl_value "net.ipv4.tcp_congestion_control"; }
get_current_qdisc()      { get_sysctl_value "net.core.default_qdisc"; }
get_current_tfo()        { get_sysctl_value "net.ipv4.tcp_fastopen";  }

check_bbr_module() {
  if grep -q "tcp_bbr" /proc/modules 2>/dev/null; then
    echo "loaded"
  elif modprobe -n tcp_bbr 2>/dev/null; then
    echo "available"
  else
    echo "unavailable"
  fi
}

is_bbr_fully_enabled() {
  [[ "$(get_current_congestion)" == "bbr" && "$(get_current_qdisc)" == "fq" ]]
}

# ==================== 【当前状态摘要显示】 ====================
print_current_summary() {
  local cc qd tfo mod full
  cc=$(get_current_congestion)
  qd=$(get_current_qdisc)
  tfo=$(get_current_tfo)
  mod=$(check_bbr_module)
  if is_bbr_fully_enabled; then
    full="${GREEN}已完全启用（BBR + fq）${NC}"
  else
    full="${YELLOW}未完全启用${NC}"
  fi

  echo -e "${BOLD}${WHITE}当前状态：${NC}"
  echo -e "  拥塞控制：${CYAN}${cc}${NC}"
  echo -e "  队列调度：${CYAN}${qd}${NC}"
  echo -e "  TFO：${CYAN}${tfo}${NC}"
  case "$mod" in
    loaded)    echo -e "  BBR 模块：${GREEN}已加载${NC}" ;;
    available) echo -e "  BBR 模块：${YELLOW}可用未加载${NC}" ;;
    *)         echo -e "  BBR 模块：${RED}不可用${NC}" ;;
  esac
  echo -e "  加速状态：${full}"
  print_separator
}

# ==================== 【配置文件冲突扫描】 ====================
scan_sysctl_conflicts() {
  local keys=("net.ipv4.tcp_congestion_control" "net.core.default_qdisc" "net.ipv4.tcp_fastopen")
  local files=()

  [[ -f /etc/sysctl.conf ]] && files+=("/etc/sysctl.conf")
  for f in /etc/sysctl.d/*.conf; do
    [[ -f "$f" ]] && files+=("$f")
  done

  local conflict=false
  local report=""

  for key in "${keys[@]}"; do
    local values=() sources=()
    for f in "${files[@]}"; do
      local line
      line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$f" 2>/dev/null | tail -n 1 || true)
      if [[ -n "$line" ]]; then
        local val
        val=$(echo "$line" | cut -d= -f2- | xargs)
        values+=("$val")
        sources+=("$f")
      fi
    done

    if [[ ${#values[@]} -gt 1 ]]; then
      local uniq
      uniq=$(printf "%s\n" "${values[@]}" | sort -u | wc -l)
      uniq=$(safe_int "$uniq" 0)
      if [[ $uniq -gt 1 ]]; then
        conflict=true
        report+="\n- ${key} 存在多份配置："
        local i
        for i in "${!values[@]}"; do
          report+="\n    ${sources[$i]} => ${values[$i]}"
        done
      fi
    fi
  done

  if [[ "$conflict" == true ]]; then
    log "ERROR" "检测到 sysctl 持久化配置冲突，建议先清理后再继续：${report}"
    return 1
  fi

  log "OK" "未发现 sysctl 持久化配置冲突"
  return 0
}

# ==============================================================================
# 【智能评估系统 - 核心增强】
# ==============================================================================

# 重置评分
reset_score() {
  SCORE_BBR=0
  SCORE_REASONS=()
}

# 添加评分
add_score() {
  local points
  points=$(safe_int "$1" 0)
  local reason="$2"
  SCORE_BBR=$((SCORE_BBR + points))
  SCORE_REASONS+=("$(printf '%+d' "$points"): $reason")
  log "SCORE" "$(printf '%+d' "$points") => $reason"
}

# ==================== 【维度1: 网络环境检测】 ====================
detect_environment() {
  log "INFO" "检测网络环境..."
  
  local env_type="unknown"
  local virt_type="unknown"
  
  # 检测虚拟化类型
  if [[ -f /sys/class/dmi/id/product_name ]]; then
    local product
    product=$(cat /sys/class/dmi/id/product_name 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
    case "$product" in
      *kvm*)      virt_type="kvm" ;;
      *vmware*)   virt_type="vmware" ;;
      *virtualbox*) virt_type="virtualbox" ;;
      *xen*)      virt_type="xen" ;;
      *hyper-v*)  virt_type="hyperv" ;;
    esac
  fi
  
  # systemd-detect-virt 更准确
  if command -v systemd-detect-virt &>/dev/null; then
    local detected
    detected=$(systemd-detect-virt 2>/dev/null || true)
    [[ -n "$detected" && "$detected" != "none" ]] && virt_type="$detected"
  fi
  
  # 检测云环境
  if [[ -f /sys/class/dmi/id/sys_vendor ]]; then
    local vendor
    vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
    case "$vendor" in
      *amazon*)     env_type="aws" ;;
      *google*)     env_type="gcp" ;;
      *microsoft*)  env_type="azure" ;;
      *alibaba*|*aliyun*) env_type="aliyun" ;;
      *tencent*)    env_type="tencent" ;;
      *digitalocean*) env_type="digitalocean" ;;
      *vultr*)      env_type="vultr" ;;
      *linode*)     env_type="linode" ;;
    esac
  fi
  
  # 检测容器
  if [[ -f /.dockerenv ]] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    virt_type="docker"
  elif [[ -f /run/.containerenv ]]; then
    virt_type="podman"
  fi
  
  # OpenVZ 检测
  if [[ -d /proc/vz ]] && [[ ! -d /proc/bc ]]; then
    virt_type="openvz"
  fi
  
  # LXC 检测
  if grep -qa container=lxc /proc/1/environ 2>/dev/null; then
    virt_type="lxc"
  fi
  
  log "INFO" "虚拟化类型: $virt_type | 云环境: $env_type"
  
  # 评分逻辑
  case "$virt_type" in
    none|kvm|vmware|qemu)
      # 物理机或完全虚拟化，BBR工作良好
      add_score 10 "完全虚拟化/物理机环境，BBR兼容性好"
      ;;
    openvz|lxc)
      # 容器虚拟化，内核共享，BBR可能受限
      add_score -30 "OpenVZ/LXC 环境，BBR 可能受限或不可用"
      ;;
    docker|podman)
      # Docker 通常继承宿主机设置
      add_score 0 "容器环境，依赖宿主机内核配置"
      ;;
    *)
      add_score 0 "未知虚拟化环境"
      ;;
  esac
  
  # 云环境通常网络优化较好
  case "$env_type" in
    aws|gcp|azure)
      add_score 5 "主流云平台，网络基础设施优良"
      ;;
    aliyun|tencent)
      add_score 5 "国内云平台"
      ;;
  esac
  
  ENV_VIRT="$virt_type"
  ENV_CLOUD="$env_type"
}

# ==================== 【维度2: RTT延迟分析】 ====================
analyze_rtt() {
  log "INFO" "分析连接延迟分布..."
  
  local ss_out
  ss_out=$(ss -ti state established 2>/dev/null || true)
  
  if [[ -z "$ss_out" ]]; then
    log "WARN" "无法获取连接信息"
    add_score 0 "无法分析RTT"
    return
  fi
  
  # 提取所有 RTT 值 (格式: rtt:123.456/5.678)
  # 使用兼容的 grep + sed 方式，避免 -P 选项
  local rtts
  rtts=$(echo "$ss_out" | grep -o 'rtt:[0-9.]*' | sed 's/rtt://' | head -n 200 || true)
  
  if [[ -z "$rtts" ]]; then
    log "WARN" "未找到RTT数据"
    add_score 0 "无RTT数据"
    return
  fi
  
  # 计算统计值
  local stats
  stats=$(echo "$rtts" | awk '
    BEGIN { sum=0; count=0; max=0; high_latency=0; low_latency=0 }
    {
      val = $1 + 0
      if (val > 0) {
        sum += val
        count++
        if (val > max) max = val
        if (val > 100) high_latency++
        if (val < 20) low_latency++
      }
    }
    END {
      if (count > 0) {
        avg = sum / count
        high_pct = high_latency * 100 / count
        low_pct = low_latency * 100 / count
        printf "%d %d %d %d %d", int(avg), int(max), int(high_pct), int(low_pct), count
      } else {
        print "0 0 0 0 0"
      }
    }
  ' 2>/dev/null || echo "0 0 0 0 0")
  
  local avg_rtt max_rtt high_latency_pct low_latency_pct rtt_count
  read -r avg_rtt max_rtt high_latency_pct low_latency_pct rtt_count <<< "$stats"
  
  # 确保都是整数
  avg_rtt=$(safe_int "$avg_rtt" 0)
  max_rtt=$(safe_int "$max_rtt" 0)
  high_latency_pct=$(safe_int "$high_latency_pct" 0)
  low_latency_pct=$(safe_int "$low_latency_pct" 0)
  rtt_count=$(safe_int "$rtt_count" 0)
  
  log "INFO" "RTT统计: 平均=${avg_rtt}ms, 最大=${max_rtt}ms, 采样=${rtt_count}条"
  log "INFO" "延迟分布: 高延迟(>100ms)=${high_latency_pct}%, 低延迟(<20ms)=${low_latency_pct}%"
  
  # 评分逻辑
  # BBR 在高延迟高带宽网络(Long Fat Network)表现更好
  if [[ $avg_rtt -gt 150 ]]; then
    add_score 25 "高延迟网络(RTT>${avg_rtt}ms)，BBR优势明显"
  elif [[ $avg_rtt -gt 80 ]]; then
    add_score 15 "中等延迟网络(RTT=${avg_rtt}ms)，BBR有一定优势"
  elif [[ $avg_rtt -gt 30 ]]; then
    add_score 5 "正常延迟网络(RTT=${avg_rtt}ms)"
  elif [[ $avg_rtt -gt 0 ]]; then
    add_score -5 "低延迟网络(RTT=${avg_rtt}ms)，CUBIC已足够"
  fi
  
  # 高延迟连接占比
  if [[ $high_latency_pct -gt 30 ]]; then
    add_score 10 "大量高延迟连接(${high_latency_pct}%)，BBR更适合"
  fi
  
  RTT_AVG="$avg_rtt"
  RTT_MAX="$max_rtt"
}

# ==================== 【维度3: 丢包与重传分析】 ====================
analyze_packet_loss() {
  log "INFO" "分析丢包与重传模式..."
  
  local ss_out
  ss_out=$(ss -ti state established 2>/dev/null | head -n $((SAMPLE_CONN * 2)) || true)
  
  if [[ -z "$ss_out" ]]; then
    log "WARN" "无法采样连接"
    add_score 0 "无法采样连接"
    return
  fi
  
  # 统计 ESTAB 行数
  local total
  total=$(echo "$ss_out" | grep -c "^ESTAB" 2>/dev/null || echo "0")
  total=$(safe_int "$total" 0)
  
  if [[ $total -le 0 ]]; then
    log "WARN" "无活跃连接"
    add_score 0 "无活跃连接可分析"
    return
  fi
  
  # 重传分析
  local retrans_conns
  retrans_conns=$(echo "$ss_out" | grep -cE "bytes_retrans:[1-9]|retrans:[1-9]|lost:[1-9]" 2>/dev/null || echo "0")
  retrans_conns=$(safe_int "$retrans_conns" 0)
  local retrans_pct
  retrans_pct=$(safe_pct "$retrans_conns" "$total")
  
  # 乱序分析
  local reorder_conns
  reorder_conns=$(echo "$ss_out" | grep -cE "reord_seen:[1-9]|dsack_dups:[1-9]" 2>/dev/null || echo "0")
  reorder_conns=$(safe_int "$reorder_conns" 0)
  local reorder_pct
  reorder_pct=$(safe_pct "$reorder_conns" "$total")
  
  # 小MSS检测
  local small_mss_conns
  small_mss_conns=$(echo "$ss_out" | awk -v cut="$MSS_SMALL_CUTOFF" '
    / mss:/ {
      n = split($0, fields)
      for (i=1; i<=n; i++) {
        if (fields[i] ~ /^mss:[0-9]+$/) {
          split(fields[i], a, ":")
          if (a[2]+0 > 0 && a[2]+0 < cut) c++
        }
      }
    }
    END { print c+0 }
  ' 2>/dev/null || echo "0")
  small_mss_conns=$(safe_int "$small_mss_conns" 0)
  local small_mss_pct
  small_mss_pct=$(safe_pct "$small_mss_conns" "$total")
  
  log "INFO" "采样 ${total} 条连接"
  log "INFO" "重传连接: ${retrans_pct}% (${retrans_conns}/${total})"
  log "INFO" "乱序连接: ${reorder_pct}% (${reorder_conns}/${total})"
  log "INFO" "小MSS连接: ${small_mss_pct}% (${small_mss_conns}/${total})"
  
  # 评分逻辑 - 重传率评估
  if [[ $retrans_pct -ge 30 ]]; then
    add_score -40 "重传率极高(${retrans_pct}%)，BBR可能加剧问题"
  elif [[ $retrans_pct -ge 20 ]]; then
    add_score -25 "重传率偏高(${retrans_pct}%)，建议谨慎"
  elif [[ $retrans_pct -ge 10 ]]; then
    add_score -10 "重传率中等(${retrans_pct}%)"
  elif [[ $retrans_pct -ge 5 ]]; then
    add_score 5 "重传率正常(${retrans_pct}%)，BBR可优化"
  else
    add_score 15 "重传率很低(${retrans_pct}%)，网络质量好"
  fi
  
  # 乱序评估 - BBR对乱序更敏感
  if [[ $reorder_pct -ge 40 ]]; then
    add_score -30 "乱序率极高(${reorder_pct}%)，可能是多路径网络"
  elif [[ $reorder_pct -ge 25 ]]; then
    add_score -15 "乱序率偏高(${reorder_pct}%)"
  elif [[ $reorder_pct -ge 10 ]]; then
    add_score -5 "有一定乱序(${reorder_pct}%)"
  fi
  
  # 小MSS评估 - 可能是代理/VPN场景
  if [[ $small_mss_pct -ge 50 ]]; then
    add_score -20 "大量小MSS连接(${small_mss_pct}%)，可能是隧道/代理"
  elif [[ $small_mss_pct -ge 30 ]]; then
    add_score -10 "较多小MSS连接(${small_mss_pct}%)"
  fi
  
  LOSS_RETRANS_PCT=$retrans_pct
  LOSS_REORDER_PCT=$reorder_pct
  LOSS_SMALLMSS_PCT=$small_mss_pct
}

# ==================== 【维度4: 带宽利用率估算】 ====================
analyze_bandwidth_utilization() {
  log "INFO" "估算带宽利用率..."
  
  local ss_out
  ss_out=$(ss -ti state established 2>/dev/null || true)
  
  if [[ -z "$ss_out" ]]; then
    add_score 0 "无法估算带宽利用率"
    return
  fi
  
  # 提取 cwnd 值，使用兼容方式
  local cwnd_data
  cwnd_data=$(echo "$ss_out" | grep -o 'cwnd:[0-9]*' | sed 's/cwnd://' | head -n 100 || true)
  
  if [[ -z "$cwnd_data" ]]; then
    add_score 0 "无cwnd数据"
    return
  fi
  
  # 计算平均cwnd和分布
  local stats
  stats=$(echo "$cwnd_data" | awk '
    BEGIN { sum=0; count=0; small=0; large=0 }
    {
      val = $1 + 0
      if (val > 0) {
        sum += val
        count++
        if (val < 10) small++
        if (val > 100) large++
      }
    }
    END {
      if (count > 0) {
        avg = sum / count
        small_pct = small * 100 / count
        large_pct = large * 100 / count
        printf "%d %d %d %d", int(avg), int(small_pct), int(large_pct), count
      } else {
        print "0 0 0 0"
      }
    }
  ' 2>/dev/null || echo "0 0 0 0")
  
  local avg_cwnd small_cwnd_pct large_cwnd_pct cwnd_count
  read -r avg_cwnd small_cwnd_pct large_cwnd_pct cwnd_count <<< "$stats"
  
  avg_cwnd=$(safe_int "$avg_cwnd" 0)
  small_cwnd_pct=$(safe_int "$small_cwnd_pct" 0)
  large_cwnd_pct=$(safe_int "$large_cwnd_pct" 0)
  cwnd_count=$(safe_int "$cwnd_count" 0)
  
  log "INFO" "CWND统计: 平均=${avg_cwnd}, 采样=${cwnd_count}条"
  log "INFO" "CWND分布: 小窗口(<10)=${small_cwnd_pct}%, 大窗口(>100)=${large_cwnd_pct}%"
  
  # 评分逻辑
  if [[ $small_cwnd_pct -gt 60 ]]; then
    add_score 15 "大量连接cwnd较小(${small_cwnd_pct}%)，BBR可能提升带宽利用"
  elif [[ $small_cwnd_pct -gt 40 ]]; then
    add_score 8 "部分连接cwnd受限(${small_cwnd_pct}%)"
  fi
  
  # 已有大量大cwnd连接，说明当前算法工作正常
  if [[ $large_cwnd_pct -gt 30 ]]; then
    add_score -5 "已有较多大cwnd连接(${large_cwnd_pct}%)，当前算法工作正常"
  fi
  
  BW_AVG_CWND="$avg_cwnd"
}

# ==================== 【维度5: 代理场景检测】 ====================
detect_proxy_scenario() {
  log "INFO" "检测代理场景..."
  
  # 统计监听端口（使用兼容方式）
  local listen_ports
  listen_ports=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -o '[0-9]*$' | sort -u || true)
  
  local proxy_port_count=0
  local high_port_count=0
  
  if [[ -n "$listen_ports" ]]; then
    while IFS= read -r port; do
      port=$(safe_int "$port" 0)
      [[ $port -le 0 ]] && continue
      case $port in
        443|8443|1080|8080|8388|8389)
          proxy_port_count=$((proxy_port_count + 1))
          ;;
      esac
      if [[ $port -ge 10000 ]]; then
        high_port_count=$((high_port_count + 1))
      fi
    done <<< "$listen_ports"
  fi
  
  # 检测常见代理程序
  local proxy_procs=0
  local proxy_list="xray v2ray trojan shadowsocks ss-server ssserver hysteria naive brook gost"
  for proc in $proxy_list; do
    if pgrep -x "$proc" &>/dev/null 2>&1 || pgrep -f "$proc" &>/dev/null 2>&1; then
      proxy_procs=$((proxy_procs + 1))
      log "INFO" "检测到代理程序: $proc"
    fi
  done
  
  # 连接数分析
  local estab_count
  estab_count=$(ss -s 2>/dev/null | awk '/estab/ {gsub(",","",$4); print $4}' | head -n1 || echo "0")
  estab_count=$(safe_int "$estab_count" 0)
  
  log "INFO" "代理端口数: $proxy_port_count, 高位端口数: $high_port_count"
  log "INFO" "代理进程数: $proxy_procs, 活跃连接数: $estab_count"
  
  # 评分逻辑
  if [[ $proxy_procs -gt 0 ]]; then
    add_score -10 "检测到代理程序(${proxy_procs}个)，需评估BBR兼容性"
  fi
  
  if [[ $proxy_port_count -ge 3 ]]; then
    add_score -5 "多个代理相关端口在监听"
  fi
  
  # 高连接数场景
  if [[ $estab_count -gt 5000 ]]; then
    add_score -5 "高并发连接(${estab_count})，切换需谨慎"
  elif [[ $estab_count -gt 1000 ]]; then
    add_score 0 "中等并发连接(${estab_count})"
  fi
  
  PROXY_DETECTED=$proxy_procs
  CONN_COUNT=$estab_count
}

# ==================== 【维度6: 网络接口分析】 ====================
analyze_network_interface() {
  log "INFO" "分析网络接口..."
  
  # 获取默认路由接口
  local default_iface
  default_iface=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)
  
  if [[ -z "$default_iface" ]]; then
    add_score 0 "无法确定默认网络接口"
    return
  fi
  
  log "INFO" "默认接口: $default_iface"
  
  # 获取接口速度
  local speed=0
  if [[ -f "/sys/class/net/${default_iface}/speed" ]]; then
    speed=$(cat "/sys/class/net/${default_iface}/speed" 2>/dev/null || echo "0")
    speed=$(safe_int "$speed" 0)
    # 某些虚拟接口返回 -1
    [[ $speed -lt 0 ]] && speed=0
  fi
  
  # 检查是否是虚拟接口
  local is_virtual=false
  case "$default_iface" in
    veth*|docker*|br-*|virbr*|tun*|tap*)
      is_virtual=true
      ;;
  esac
  
  if [[ -L "/sys/class/net/${default_iface}/device" ]]; then
    local driver
    driver=$(readlink "/sys/class/net/${default_iface}/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)
    case "$driver" in
      virtio*|vif|xen*)
        is_virtual=true
        ;;
    esac
  fi
  
  log "INFO" "接口速度: ${speed}Mbps, 虚拟接口: $is_virtual"
  
  # 评分逻辑
  if [[ $speed -ge 10000 ]]; then
    add_score 10 "高速网络(${speed}Mbps)，BBR可充分利用"
  elif [[ $speed -ge 1000 ]]; then
    add_score 5 "千兆网络(${speed}Mbps)"
  elif [[ $speed -gt 0 && $speed -lt 100 ]]; then
    add_score -5 "低速网络(${speed}Mbps)"
  fi
  
  NET_IFACE="$default_iface"
  NET_SPEED="$speed"
}

# ==================== 【综合智能决策】 ====================
intelligent_decision() {
  log "INFO" "开始多维度智能评估..."
  print_separator
  
  reset_score
  
  # 执行所有维度分析
  detect_environment
  analyze_rtt
  analyze_packet_loss
  analyze_bandwidth_utilization
  detect_proxy_scenario
  analyze_network_interface
  
  print_separator
  log "INFO" "评估完成，计算最终得分..."
  
  # 显示所有评分因素
  echo -e "\n${BOLD}${WHITE}评分明细：${NC}"
  for reason in "${SCORE_REASONS[@]}"; do
    local pts="${reason%%:*}"
    local desc="${reason#*: }"
    if [[ "$pts" == *-* ]]; then
      echo -e "  ${RED}${pts}${NC}: $desc"
    elif [[ "$pts" == "+0" ]]; then
      echo -e "  ${WHITE}${pts}${NC}: $desc"
    else
      echo -e "  ${GREEN}${pts}${NC}: $desc"
    fi
  done
  
  echo ""
  print_separator
  
  # 最终决策
  local final_decision
  local decision_confidence
  
  if [[ $SCORE_BBR -ge 30 ]]; then
    final_decision="bbr"
    decision_confidence="高"
    CHOOSE_REASON="综合评分 ${SCORE_BBR} (≥30)，强烈建议启用 BBR"
  elif [[ $SCORE_BBR -ge 10 ]]; then
    final_decision="bbr"
    decision_confidence="中"
    CHOOSE_REASON="综合评分 ${SCORE_BBR} (10~29)，建议启用 BBR"
  elif [[ $SCORE_BBR -ge -10 ]]; then
    final_decision="bbr"
    decision_confidence="低"
    CHOOSE_REASON="综合评分 ${SCORE_BBR} (-10~9)，可尝试 BBR"
  elif [[ $SCORE_BBR -ge -30 ]]; then
    final_decision="stable"
    decision_confidence="中"
    CHOOSE_REASON="综合评分 ${SCORE_BBR} (-30~-11)，建议使用 CUBIC"
  else
    final_decision="stable"
    decision_confidence="高"
    CHOOSE_REASON="综合评分 ${SCORE_BBR} (<-30)，强烈建议使用 CUBIC"
  fi
  
  CHOSEN_PROFILE="$final_decision"
  
  # 显示决策结果
  echo -e "${BOLD}${WHITE}智能决策结果：${NC}"
  echo -e "  综合评分：${CYAN}${SCORE_BBR}${NC}"
  echo -e "  推荐算法：${CYAN}$([ "$final_decision" == "bbr" ] && echo "BBR" || echo "CUBIC")${NC}"
  echo -e "  置信度：${CYAN}${decision_confidence}${NC}"
  echo -e "  决策依据：${CYAN}${CHOOSE_REASON}${NC}"
  print_separator
  
  return 0
}

# ==================== 【备份】 ====================
create_backup() {
  local backup_file="${BACKUP_DIR}/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
  local tmp
  tmp=$(mktemp -d) || { log "ERROR" "无法创建临时目录"; return 1; }

  log "INFO" "正在创建备份"
  sysctl -a 2>/dev/null | grep -E "^net\.(core|ipv4)" | sed 's/ = /=/' > "${tmp}/sysctl_current.conf" || true

  [[ -f "$SYSCTL_BBR_CONF" ]] && cp "$SYSCTL_BBR_CONF" "$tmp/" 2>/dev/null || true
  [[ -f "$SYSCTL_STABLE_CONF" ]] && cp "$SYSCTL_STABLE_CONF" "$tmp/" 2>/dev/null || true
  [[ -f "$CONNTRACK_CONF" ]] && cp "$CONNTRACK_CONF" "$tmp/" 2>/dev/null || true
  [[ -f "$MODULES_BBR_CONF" ]] && cp "$MODULES_BBR_CONF" "$tmp/" 2>/dev/null || true

  {
    echo "Backup Time: $(date)"
    echo "OS: ${OS_PRETTY:-Unknown}"
    echo "Kernel: ${KERNEL_VERSION:-Unknown}"
    echo "Congestion: $(get_current_congestion)"
    echo "Qdisc: $(get_current_qdisc)"
    echo "TFO: $(get_current_tfo)"
    echo "Script Version: $SCRIPT_VERSION"
    echo "Score: $SCORE_BBR"
  } > "${tmp}/system_info.txt" 2>/dev/null || true

  if tar -czf "$backup_file" -C "$tmp" . 2>/dev/null; then
    log "OK" "备份创建完成：$backup_file"
  else
    log "ERROR" "备份创建失败"
    rm -rf "$tmp"
    return 1
  fi

  rm -rf "$tmp"
  return 0
}

# ==================== 【配置生成】 ====================
get_system_memory_mb() {
  local mem_kb
  mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  mem_kb=$(safe_int "$mem_kb" 0)
  echo $((mem_kb / 1024))
}

calculate_buffers() {
  local mem_mb
  mem_mb=$(get_system_memory_mb)
  if [[ $mem_mb -le 0 ]]; then
    mem_mb=1024
    log "WARN" "无法获取内存大小，使用默认 1024MB"
  fi

  if [[ $mem_mb -lt 1024 ]]; then
    RMEM_MAX=4194304
    WMEM_MAX=4194304
    TCP_RMEM="4096 65536 4194304"
    TCP_WMEM="4096 16384 4194304"
    TCP_MEM="32768 65536 131072"
  elif [[ $mem_mb -lt 4096 ]]; then
    RMEM_MAX=8388608
    WMEM_MAX=8388608
    TCP_RMEM="4096 131072 8388608"
    TCP_WMEM="4096 16384 8388608"
    TCP_MEM="65536 131072 262144"
  else
    RMEM_MAX=16777216
    WMEM_MAX=16777216
    TCP_RMEM="4096 131072 16777216"
    TCP_WMEM="4096 16384 16777216"
    TCP_MEM="262144 524288 1048576"
  fi
}

generate_bbr_config() {
  calculate_buffers
  cat <<EOF
# ============================================================
# 【BBR 加速配置】
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# MemoryMB: $(get_system_memory_mb)
# Profile: bbr-boost
# Score: $SCORE_BBR
# ============================================================

net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

net.core.rmem_default = 1048576
net.core.rmem_max = ${RMEM_MAX}
net.core.wmem_default = 1048576
net.core.wmem_max = ${WMEM_MAX}
net.ipv4.tcp_rmem = ${TCP_RMEM}
net.ipv4.tcp_wmem = ${TCP_WMEM}
net.ipv4.tcp_mem  = ${TCP_MEM}

net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1

net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

net.ipv4.ip_local_port_range = 1024 65535

net.ipv4.tcp_max_orphans = 65535
net.ipv4.tcp_max_tw_buckets = 65535

net.ipv4.tcp_mtu_probing = 1
EOF
}

generate_stable_config() {
  cat <<EOF
# ============================================================
# 【稳定代理配置】
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Profile: proxy-stable
# Score: $SCORE_BBR
# ============================================================

net.ipv4.tcp_congestion_control = cubic
net.core.default_qdisc = fq_codel
net.ipv4.tcp_fastopen = 0
EOF
}

generate_conntrack_config() {
  cat <<'EOF'
# ============================================================
# 【Conntrack 优化配置（可选）】
# Profile: conntrack-tuning
# ============================================================

net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
EOF
}

# ==================== 【应用配置】 ====================
check_sysctl_param_exists() { sysctl "$1" >/dev/null 2>&1; }

apply_sysctl_file_safely() {
  local file="$1"
  local applied=0 failed=0 skipped=0

  log "INFO" "正在应用 sysctl 配置：$file"

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line//[[:space:]]/}" ]] && continue

    local key val
    key=$(echo "$line" | cut -d= -f1 | xargs)
    val=$(echo "$line" | cut -d= -f2- | xargs)
    [[ -z "$key" ]] && continue

    if [[ "$DRY_RUN" == true ]]; then
      echo "[DRY-RUN] sysctl -w ${key}=${val}"
      continue
    fi

    if check_sysctl_param_exists "$key"; then
      if sysctl -w "${key}=${val}" >/dev/null 2>&1; then
        applied=$((applied + 1))
      else
        failed=$((failed + 1))
        log "WARN" "应用失败：${key}"
      fi
    else
      skipped=$((skipped + 1))
    fi
  done < "$file"

  log "INFO" "应用完成：成功 ${applied} 项，失败 ${failed} 项，跳过 ${skipped} 项"
  return 0
}

load_bbr_module() {
  local mod_status
  mod_status=$(check_bbr_module)
  if [[ "$mod_status" == "unavailable" ]]; then
    log "ERROR" "BBR 模块不可用"
    return 1
  fi

  log "INFO" "正在加载 BBR 模块"
  if [[ "$DRY_RUN" == true ]]; then
    echo "[DRY-RUN] modprobe tcp_bbr"
    return 0
  fi

  modprobe tcp_bbr 2>/dev/null || {
    log "ERROR" "BBR 模块加载失败"
    return 1
  }

  mkdir -p "$(dirname "$MODULES_BBR_CONF")" 2>/dev/null || true
  if [[ ! -f "$MODULES_BBR_CONF" ]]; then
    echo "tcp_bbr" > "$MODULES_BBR_CONF"
  fi

  log "OK" "BBR 模块已加载"
  return 0
}

write_profile_files() {
  local profile="$1"

  if [[ "$DRY_RUN" == true ]]; then
    log "INFO" "预览模式：将写入配置文件（不实际写入）"
    return 0
  fi

  mkdir -p /etc/sysctl.d 2>/dev/null || true

  if [[ "$profile" == "bbr" ]]; then
    rm -f "$SYSCTL_STABLE_CONF" 2>/dev/null || true
    log "INFO" "已移除稳定配置文件（如存在）：$SYSCTL_STABLE_CONF"

    generate_bbr_config > "$SYSCTL_BBR_CONF"
    log "OK" "已写入 BBR 配置：$SYSCTL_BBR_CONF"
  else
    generate_stable_config > "$SYSCTL_STABLE_CONF"
    log "OK" "已写入稳定配置：$SYSCTL_STABLE_CONF"

    rm -f "$SYSCTL_BBR_CONF" 2>/dev/null || true
    log "INFO" "已移除 BBR 配置文件（如存在）：$SYSCTL_BBR_CONF"
  fi

  return 0
}

apply_profile_runtime() {
  local profile="$1"

  if [[ "$profile" == "bbr" ]]; then
    load_bbr_module || return 1
    apply_sysctl_file_safely "$SYSCTL_BBR_CONF"
  else
    apply_sysctl_file_safely "$SYSCTL_STABLE_CONF"
  fi

  if check_sysctl_param_exists "net.netfilter.nf_conntrack_max"; then
    if [[ "$DRY_RUN" == true ]]; then
      log "INFO" "预览模式：将应用 conntrack 优化（不实际写入）"
    else
      generate_conntrack_config > "$CONNTRACK_CONF"
      apply_sysctl_file_safely "$CONNTRACK_CONF"
      log "OK" "已应用 conntrack 优化"
    fi
  else
    log "INFO" "未检测到 conntrack 参数，跳过 conntrack 优化"
  fi

  return 0
}

# ==================== 【应用后校验 + 回滚】 ====================
post_apply_validate() {
  local chosen="$1"

  local cc qd
  cc=$(get_current_congestion)
  qd=$(get_current_qdisc)

  if [[ "$chosen" == "bbr" ]]; then
    if [[ "$cc" != "bbr" || "$qd" != "fq" ]]; then
      log "WARN" "应用后校验失败：当前 ${cc}+${qd}，将回滚稳定配置"
      [[ "$ENABLE_ROLLBACK" == true ]] && apply_profile_runtime "stable"
      return 1
    fi
  fi

  log "OK" "应用后校验通过"
  return 0
}

# ==================== 【状态显示】 ====================
show_status() {
  print_header
  get_os_info
  get_kernel_info
  print_current_summary

  log "INFO" "系统信息：$OS_PRETTY"
  log "INFO" "内核版本：$KERNEL_VERSION"

  if [[ -f "$SYSCTL_STABLE_CONF" ]]; then log "INFO" "稳定配置文件：$SYSCTL_STABLE_CONF"; else log "WARN" "稳定配置文件不存在"; fi
  if [[ -f "$SYSCTL_BBR_CONF" ]]; then log "INFO" "BBR 配置文件：$SYSCTL_BBR_CONF"; else log "INFO" "BBR 配置文件不存在"; fi
  if [[ -f "$CONNTRACK_CONF" ]]; then log "INFO" "Conntrack 配置文件：$CONNTRACK_CONF"; else log "INFO" "Conntrack 配置文件不存在"; fi
  print_separator
}

# ==================== 【智能自动模式】 ====================
auto_mode() {
  print_header
  get_os_info
  get_kernel_info
  print_current_summary

  log "INFO" "开始智能自动模式（增强版）"

  check_system_compatibility || return 1
  check_kernel_support || return 1

  scan_sysctl_conflicts || return 1

  # 使用新的多维度智能决策
  intelligent_decision

  if [[ "$CHOSEN_PROFILE" == "bbr" ]]; then
    log "OK" "智能决策：选择 BBR (评分: ${SCORE_BBR})"
  else
    log "OK" "智能决策：选择稳定配置 CUBIC (评分: ${SCORE_BBR})"
  fi

  create_backup || log "WARN" "备份失败（将继续执行）"

  write_profile_files "$CHOSEN_PROFILE" || return 1

  if ! apply_profile_runtime "$CHOSEN_PROFILE"; then
    log "ERROR" "应用失败，将切换到稳定配置"
    apply_profile_runtime "stable" || true
    return 1
  fi

  [[ "$DRY_RUN" == true ]] && { log "OK" "预览模式结束（未实际更改系统）"; return 0; }

  post_apply_validate "$CHOSEN_PROFILE" || true

  log "INFO" "应用完成后的当前状态如下"
  print_current_summary

  if is_bbr_fully_enabled; then
    log "OK" "最终结果：BBR 已完全启用"
  else
    log "OK" "最终结果：已使用稳定配置"
  fi

  return 0
}

# ==================== 【仅分析模式】 ====================
analyze_only() {
  print_header
  get_os_info
  get_kernel_info
  print_current_summary
  
  log "INFO" "仅分析模式 - 不做任何更改"
  
  intelligent_decision
  
  echo ""
  log "INFO" "分析完成。如需应用，请使用 --auto 参数"
}

# ==================== 【强制启用/禁用】 ====================
force_enable_bbr() {
  print_header
  get_os_info
  get_kernel_info
  print_current_summary

  log "WARN" "强制启用 BBR（不参考智能建议）"

  check_system_compatibility || return 1
  check_kernel_support || return 1
  scan_sysctl_conflicts || return 1

  create_backup || log "WARN" "备份失败（将继续执行）"

  write_profile_files "bbr" || return 1
  apply_profile_runtime "bbr" || return 1

  [[ "$DRY_RUN" == true ]] && { log "OK" "预览模式结束"; return 0; }

  post_apply_validate "bbr" || true

  log "INFO" "应用完成后的当前状态如下"
  print_current_summary
  return 0
}

disable_to_stable() {
  print_header
  get_os_info
  get_kernel_info
  print_current_summary

  log "INFO" "切换到稳定配置并禁用 BBR 持久化"

  create_backup || log "WARN" "备份失败（将继续执行）"

  if [[ "$DRY_RUN" == true ]]; then
    echo "[DRY-RUN] write stable conf + remove bbr conf + apply stable"
    return 0
  fi

  write_profile_files "stable" || return 1
  apply_profile_runtime "stable" || return 1

  rm -f "$MODULES_BBR_CONF" 2>/dev/null || true
  rm -f "$CONNTRACK_CONF" 2>/dev/null || true

  log "OK" "已切换到稳定配置"
  log "INFO" "当前状态如下"
  print_current_summary
  return 0
}

# ==================== 【菜单】 ====================
show_menu() {
  print_header
  get_os_info
  get_kernel_info
  print_current_summary

  echo -e "${BOLD}${WHITE}请选择操作：${NC}"
  echo ""
  echo -e "  ${GREEN}1)${NC} 🚀 智能自动模式（多维度评估 + 自动选择）"
  echo -e "  ${GREEN}2)${NC} 🔍 仅分析（不做更改，只显示建议）"
  echo -e "  ${GREEN}3)${NC} 📊 查看状态"
  echo -e "  ${GREEN}4)${NC} ⚠️  强制启用 BBR（忽略建议）"
  echo -e "  ${GREEN}5)${NC} ✅ 切换到稳定配置（CUBIC）"
  echo -e "  ${GREEN}6)${NC} 🔧 扫描 sysctl 配置冲突"
  echo -e "  ${GREEN}7)${NC} 🧪 预览智能自动模式（Dry-Run）"
  echo -e "  ${GREEN}0)${NC} 退出"
  echo ""
  print_separator
}

main_menu() {
  while true; do
    show_menu
    echo -ne "${BOLD}请输入选项 [0-7]: ${NC}"
    read -r choice
    case "$choice" in
      1) auto_mode; echo ""; read -rp "按 Enter 返回..." ;;
      2) analyze_only; echo ""; read -rp "按 Enter 返回..." ;;
      3) show_status; echo ""; read -rp "按 Enter 返回..." ;;
      4) force_enable_bbr; echo ""; read -rp "按 Enter 返回..." ;;
      5) disable_to_stable; echo ""; read -rp "按 Enter 返回..." ;;
      6) scan_sysctl_conflicts; echo ""; read -rp "按 Enter 返回..." ;;
      7)
        DRY_RUN=true
        auto_mode
        DRY_RUN=false
        echo ""; read -rp "按 Enter 返回..."
        ;;
      0|q|Q) log "INFO" "退出"; exit 0 ;;
      *) log "ERROR" "无效选项"; sleep 1 ;;
    esac
  done
}

# ==================== 【帮助】 ====================
show_help() {
  cat <<EOF
Usage: $0 [options]

Options:
  --auto          Intelligent auto mode (multi-dimensional analysis)
  --analyze       Analyze only (no changes, show recommendation)
  --status        Show current status
  --force-bbr     Force enable BBR (ignores recommendations)
  --stable        Switch to stable profile (CUBIC)
  --scan          Scan sysctl persistence conflicts
  --dry-run       Preview actions without changing system
  --quiet         Quiet mode
  --debug         Debug logs
  --help          Show help

Scoring System:
  Score >= 30    : Strongly recommend BBR
  Score 10-29    : Recommend BBR
  Score -10 to 9 : BBR acceptable
  Score -30 to -11: Recommend CUBIC
  Score < -30    : Strongly recommend CUBIC
EOF
}

# ==================== 【主入口】 ====================
main() {
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

  get_os_info
  get_kernel_info

  case "${1:-}" in
    --auto) auto_mode ;;
    --analyze) analyze_only ;;
    --status) show_status ;;
    --force-bbr) force_enable_bbr ;;
    --stable) disable_to_stable ;;
    --scan) scan_sysctl_conflicts ;;
    --help|-h) show_help ;;
    "") main_menu ;;
    *) log "ERROR" "未知选项"; show_help; exit 1 ;;
  esac
}

main "$@"
