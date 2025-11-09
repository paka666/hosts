#!/usr/bin/env bash
set -euo pipefail

mkdir -p temp srs srs/json srs/json/same

# 检查必要依赖
check_dependencies() {
  local deps=("jq" "wget" "sing-box" "python3")
  local missing=()
  
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      missing+=("$dep")
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
    echo "Error: Missing dependencies: ${missing[*]}"
    echo "Please install them before running this script."
    exit 1
  fi

  # 检查Python ipaddress模块
  if ! python3 -c "import ipaddress" >/dev/null 2>&1; then
    echo "Error: Python ipaddress module is required"
    exit 1
  fi
}

echo "Checking dependencies..."
check_dependencies

# 预处理阶段
preprocess_ruleset() {
  local base_url="$1"
  local exclude_url="$2"
  local output_file="$3"
  local output_type="$4"

  echo "Preprocessing: $base_url - $exclude_url -> $output_file ($output_type)"

  local base_temp="temp/base_$$.json"
  local exclude_temp="temp/exclude_$$.json"

  wget -q --timeout=180 --tries=3 "$base_url" -O "$base_temp" || return 1
  wget -q --timeout=180 --tries=3 "$exclude_url" -O "$exclude_temp" || return 1

  if [ "$output_type" = "cn" ]; then
    # 从基础文件中移除排除文件中的规则（cn 情况）
    jq --slurpfile exclude "$exclude_temp" '
      .rules as $base_rules |
      $exclude[0].rules as $exclude_rules |
      {
        version: 1,
        rules: $base_rules | map(
          . as $rule |
          if ($exclude_rules | any(. == $rule)) then
            empty
          else
            $rule
          end
        )
      }
    ' "$base_temp" > "$output_file"
  else
    # 从基础文件中移除排除文件中的规则（!cn 情况）
    jq --slurpfile exclude "$exclude_temp" '
      .rules as $base_rules |
      $exclude[0].rules as $exclude_rules |
      {
        version: 1,
        rules: $base_rules | map(
          . as $rule |
          if ($exclude_rules | any(. == $rule)) then
            empty
          else
            $rule
          end
        )
      }
    ' "$base_temp" > "$output_file"
  fi

  rm -f "$base_temp" "$exclude_temp"

  if jq empty "$output_file" >/dev/null 2>&1; then
    echo "Successfully generated: $output_file"
    return 0
  else
    echo "Error: Generated invalid JSON for $output_file"
    rm -f "$output_file"
    return 1
  fi
}

# 预处理配置数组格式: "基础文件URL" "排除文件URL" "输出文件路径" "输出类型"
preprocess_configs=(
# game
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-cn@!cn.json"
  "srs/json/geosite-category-games-cn@cn2.json"
  "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-!cn@cn.json"
  "srs/json/geosite-category-games-!cn@!cn.json"
  "!cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-game-platforms-download.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-game-platforms-download@cn.json"
  "srs/json/game-platforms-download@!cn.json"
  "!cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-epicgames.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-epicgames@cn.json"
  "srs/json/geosite-epicgames@!cn.json"
  "!cn"
# ai
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ai-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ai-cn@!cn.json"
  "srs/json/geosite-category-ai-cn@cn.json"
  "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-doubao.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-doubao@!cn.json"
  "srs/json/doubao@cn.json"
  "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-jetbrains.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-jetbrains@cn.json"
  "srs/json/jetbrains@!cn.json"
  "!cn"
# network
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-cn@!cn.json"
  "srs/json/geosite-category-social-media-cn@cn.json"
  "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-bank-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-bank-cn@!cn.json"
  "srs/json/geosite-category-bank-cn@cn.json"
  "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-dev-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-dev-cn@!cn.json"
  "srs/json/geosite-category-dev-cn@cn2.json"
  "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-entertainment-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-entertainment-cn@!cn.json"
  "srs/json/geosite-category-entertainment-cn@cn2.json"
  "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-!cn@cn.json"
  "srs/json/geosite-category-social-media-!cn@!cn.json"
  "!cn"
)

echo "Starting preprocessing..."
for ((i=0; i<${#preprocess_configs[@]}; i+=4)); do
  base_url="${preprocess_configs[i]}"
  exclude_url="${preprocess_configs[i+1]}"
  output_file="${preprocess_configs[i+2]}"
  output_type="${preprocess_configs[i+3]}"

  preprocess_ruleset "$base_url" "$exclude_url" "$output_file" "$output_type" || echo "Failed to process: $base_url"
done

echo "Preprocessing completed!"

# 优化JSON文件，去重排序合并，ip_cidr合并
optimize_json_file() {
  local json_file="$1"
  local temp_file="${json_file}.tmp"
  local before_size=$(stat -c %s "$json_file" 2>/dev/null || echo 0)

  echo "Optimizing JSON file: $json_file (before size: $before_size bytes)"

  if [ ! -f "$json_file" ]; then
    echo " File not found, skipping"
    return 0
  fi

  if ! jq empty "$json_file" >/dev/null 2>&1; then
    echo " Invalid JSON, skipping optimization"
    return 1
  fi

  # 提取所有可能的字段并检查未知字段
  local all_fields
  all_fields=$(jq -r '.rules[0] | keys[]?' "$json_file" 2>/dev/null | sort | uniq)

  local known_fields=("domain" "domain_suffix" "domain_keyword" "domain_regex" "ip_cidr")
  local unknown_fields=()

  for field in $all_fields; do
    if [[ ! " ${known_fields[@]} " =~ " ${field} " ]]; then
      unknown_fields+=("$field")
    fi
  done

  if [ ${#unknown_fields[@]} -gt 0 ]; then
    echo " Error: Unknown fields found: ${unknown_fields[*]}. Stopping script to update."
    exit 1
  fi

  # 修复的jq处理逻辑 - 处理字符串和数组的混合情况
  jq '
    # 确保输入是数组，处理字符串和数组混合的情况
    def ensure_array:
      if . == null then []
      elif type == "string" then [.]
      elif type == "array" then 
        map(if type == "string" then . else tostring end)
      else [tostring] end;

    # 处理domain：确保是数组，去掉首位的点，去重排序
    def process_domain: 
      ensure_array | map(if startswith(".") then .[1:] else . end) | unique | sort;

    # 处理domain_suffix：确保是数组，确保有首位的点，去重排序  
    def process_domain_suffix:
      ensure_array | map(if startswith(".") then . else "." + . end) | unique | sort;

    # 处理其他字段：确保是数组，去重排序
    def process_other:
      ensure_array | unique | sort;

    if .rules then
      .rules |= map(
        . as $rule |
        {
          # 单独处理每个字段，使用空数组作为默认值
          domain: (($rule.domain // []) | process_domain),
          domain_suffix: (($rule.domain_suffix // []) | process_domain_suffix),
          domain_keyword: (($rule.domain_keyword // []) | process_other),
          domain_regex: (($rule.domain_regex // []) | process_other),
          ip_cidr: (($rule.ip_cidr // []) | process_other)
        }
      )
    else
      .
    end
  ' "$json_file" > "$temp_file" && mv "$temp_file" "$json_file"

  # 第二步：在domain和domain_suffix之间建立对应关系
  jq '
    def ensure_array:
      if . == null then []
      elif type == "string" then [.]
      elif type == "array" then 
        map(if type == "string" then . else tostring end)
      else [tostring] end;

    if .rules then
      .rules |= map(
        . as $rule |
        {
          # 从domain生成domain_suffix
          domain_suffix: ((($rule.domain_suffix // []) | ensure_array) + (($rule.domain // []) | ensure_array | map("." + .)) | unique | sort),
          # 从domain_suffix生成domain  
          domain: ((($rule.domain // []) | ensure_array) + (($rule.domain_suffix // []) | ensure_array | map(if startswith(".") then .[1:] else . end)) | unique | sort),
          # 其他字段保持不变
          domain_keyword: ($rule.domain_keyword // []) | ensure_array,
          domain_regex: ($rule.domain_regex // []) | ensure_array,
          ip_cidr: ($rule.ip_cidr // []) | ensure_array
        }
      )
    else
      .
    end
  ' "$json_file" > "$temp_file" && mv "$temp_file" "$json_file"

  # 第三步：合并ip_cidr网段 - 使用文件传递数据避免参数过长
  local ip_cidr_json=$(jq '.rules[0].ip_cidr // []' "$json_file")
  if [ "$ip_cidr_json" != "[]" ] && [ "$ip_cidr_json" != "null" ]; then
    # 创建临时文件来传递数据，避免参数过长
    local ip_temp_file="temp/ip_cidr_$$.json"
    echo "$ip_cidr_json" > "$ip_temp_file"

    local merged_ip_cidr
    merged_ip_cidr=$(python3 -c "
import ipaddress
import json
import sys

def merge_ip_cidrs(ip_list):
    try:
        if not ip_list:
            return []

        # 分离IPv4和IPv6
        ipv4_networks = []
        ipv6_networks = []

        for ip_cidr in ip_list:
            try:
                network = ipaddress.ip_network(ip_cidr, strict=False)
                if network.version == 4:
                    ipv4_networks.append(network)
                else:
                    ipv6_networks.append(network)
            except ValueError as e:
                # 忽略无效的CIDR
                continue

        # 分别合并IPv4和IPv6
        merged_ipv4 = list(ipaddress.collapse_addresses(ipv4_networks))
        merged_ipv6 = list(ipaddress.collapse_addresses(ipv6_networks))

        # 合并结果
        result = [str(net) for net in merged_ipv4 + merged_ipv6]
        return result
    except Exception as e:
        print(f'Error merging IP CIDRs: {e}', file=sys.stderr)
        return ip_list  # 出错时返回原列表

# 从文件读取数据
try:
    with open(sys.argv[1], 'r') as f:
        ip_cidrs = json.load(f)
    merged = merge_ip_cidrs(ip_cidrs)
    print(json.dumps(merged))
except Exception as e:
    print('[]')
    print(f'File processing error: {e}', file=sys.stderr)
" "$ip_temp_file")

    # 清理临时文件
    rm -f "$ip_temp_file"

    # 更新回JSON
    if [ "$merged_ip_cidr" != "[]" ]; then
      jq ".rules[0].ip_cidr = $merged_ip_cidr" "$json_file" > "$temp_file" && mv "$temp_file" "$json_file"
    fi
  fi

  local after_size=$(stat -c %s "$json_file" 2>/dev/null || echo 0)
  local reduction=$((before_size - after_size))
  echo " Optimization completed (after size: $after_size bytes, reduced: $reduction bytes)"
}

# 修复的对比CN和!CN分组函数
compare_cn_pairs() {
  local cn_file="$1"
  local noncn_file="$2"
  local output_file="$3"

  echo "Comparing CN pairs: $cn_file vs $noncn_file"

  if [ ! -f "$cn_file" ] || [ ! -f "$noncn_file" ]; then
    echo " One or both files not found, skipping comparison"
    return 0
  fi

  # 验证文件格式
  if ! jq empty "$cn_file" >/dev/null 2>&1 || ! jq empty "$noncn_file" >/dev/null 2>&1; then
    echo " One or both files have invalid JSON, skipping comparison"
    return 0
  fi

  # 调试信息：显示文件大小
  local cn_size=$(stat -c %s "$cn_file" 2>/dev/null || echo 0)
  local noncn_size=$(stat -c %s "$noncn_file" 2>/dev/null || echo 0)
  echo " File sizes - CN: $cn_size bytes, !CN: $noncn_size bytes"

  # 找出相同部分
  local same_temp="${output_file}.temp"

  # 使用更健壮的对比逻辑
  if ! jq -n --argfile cn "$cn_file" --argfile noncn "$noncn_file" '
    # 安全获取字段，处理可能不存在的字段
    def safe_get_field($file; $field):
      if $file.rules and ($file.rules | length > 0) and $file.rules[0][$field] then 
        $file.rules[0][$field] 
      else 
        [] 
      end;

    # 查找共同元素
    def find_common($a; $b):
      if ($a | length == 0) or ($b | length == 0) then
        []
      else
        $a | [.[] | select(IN($b[]))]
      end;

    # 获取两个文件的所有字段
    ($cn | safe_get_field(.; "domain")) as $cn_domain |
    ($noncn | safe_get_field(.; "domain")) as $noncn_domain |
    ($cn | safe_get_field(.; "domain_suffix")) as $cn_domain_suffix |
    ($noncn | safe_get_field(.; "domain_suffix")) as $noncn_domain_suffix |
    ($cn | safe_get_field(.; "domain_keyword")) as $cn_domain_keyword |
    ($noncn | safe_get_field(.; "domain_keyword")) as $noncn_domain_keyword |
    ($cn | safe_get_field(.; "domain_regex")) as $cn_domain_regex |
    ($noncn | safe_get_field(.; "domain_regex")) as $noncn_domain_regex |
    ($cn | safe_get_field(.; "ip_cidr")) as $cn_ip_cidr |
    ($noncn | safe_get_field(.; "ip_cidr")) as $noncn_ip_cidr |

    # 计算共同部分
    {
      version: 1,
      rules: [
        {
          domain: find_common($cn_domain; $noncn_domain),
          domain_suffix: find_common($cn_domain_suffix; $noncn_domain_suffix),
          domain_keyword: find_common($cn_domain_keyword; $noncn_domain_keyword),
          domain_regex: find_common($cn_domain_regex; $noncn_domain_regex),
          ip_cidr: find_common($cn_ip_cidr; $noncn_ip_cidr)
        }
      ]
    }
  ' > "$same_temp"; then
    echo " Failed to compare files, skipping"
    rm -f "$same_temp"
    return 0
  fi

  # 调试信息：显示共同部分的大小
  local same_size=$(stat -c %s "$same_temp" 2>/dev/null || echo 0)
  echo " Common parts temp file size: $same_size bytes"

  # 更宽松的空文件检查 - 只要有一个字段有内容就不为空
  local is_empty=$(jq '
    .rules[0] | 
    [.domain, .domain_suffix, .domain_keyword, .domain_regex, .ip_cidr] | 
    map(if . then length else 0 end) | 
    add == 0
  ' "$same_temp" 2>/dev/null)

  if [ "$is_empty" = "true" ]; then
    echo " No common parts found between $(basename "$cn_file") and $(basename "$noncn_file")"
    # 调试：显示各字段的长度
    jq '.rules[0] | with_entries(.value |= length)' "$same_temp" 2>/dev/null || echo " Cannot display field lengths"
    rm -f "$same_temp"
    return 0
  fi

  # 保存共同部分文件
  mv "$same_temp" "$output_file"
  local final_size=$(stat -c %s "$output_file" 2>/dev/null || echo 0)
  echo " Common parts saved to: $output_file ($final_size bytes)"

  # 显示共同部分的统计信息
  echo " Common parts statistics:"
  jq '.rules[0] | with_entries(.value |= length)' "$output_file" 2>/dev/null || echo " Cannot display statistics"

  # 从原文件中移除相同部分（使用更安全的方法）
  echo " Removing common parts from original files..."

  for file in "$cn_file" "$noncn_file"; do
    local temp_file="${file}.compare_tmp"
    if jq --argfile common "$output_file" '
      def safe_remove($arr; $common_arr):
        if $arr and $common_arr then 
          $arr - $common_arr 
        else 
          $arr 
        end;
      
      if .rules and (.rules | length > 0) then
        .rules[0].domain = safe_remove(.rules[0].domain; $common.rules[0].domain) |
        .rules[0].domain_suffix = safe_remove(.rules[0].domain_suffix; $common.rules[0].domain_suffix) |
        .rules[0].domain_keyword = safe_remove(.rules[0].domain_keyword; $common.rules[0].domain_keyword) |
        .rules[0].domain_regex = safe_remove(.rules[0].domain_regex; $common.rules[0].domain_regex) |
        .rules[0].ip_cidr = safe_remove(.rules[0].ip_cidr; $common.rules[0].ip_cidr)
      else
        .
      end
    ' "$file" > "$temp_file"; then
      mv "$temp_file" "$file"
      echo "  Updated: $(basename "$file")"
    else
      echo "  Failed to update: $(basename "$file")"
      rm -f "$temp_file"
    fi
  done

  echo " Comparison completed for $(basename "$cn_file") and $(basename "$noncn_file")"
}

# 优化所有JSON文件并对比CN/!CN分组
echo "Starting operation A: JSON optimization and CN/!CN comparison..."

# 首先优化所有现有的JSON文件
for json_file in srs/json/*.json; do
  if [ -f "$json_file" ] && [[ "$json_file" != *.bak.* ]]; then
    optimize_json_file "$json_file"
  fi
done

# 在对比CN和!CN分组之前添加调试
echo "=== Debug: Before CN/!CN comparison ==="
for pair in "ai-cn:ai-noncn" "games-cn:games-noncn" "network-cn:network-noncn"; do
  cn_file="srs/json/$(echo $pair | cut -d: -f1).json"
  noncn_file="srs/json/$(echo $pair | cut -d: -f2).json"
  
  if [ -f "$cn_file" ] && [ -f "$noncn_file" ]; then
    echo "Checking $cn_file and $noncn_file:"
    # 显示各字段的数量
    for field in domain domain_suffix domain_keyword domain_regex ip_cidr; do
      cn_count=$(jq -r ".rules[0].$field | length" "$cn_file" 2>/dev/null || echo "0")
      noncn_count=$(jq -r ".rules[0].$field | length" "$noncn_file" 2>/dev/null || echo "0")
      echo "  $field: CN=$cn_count, !CN=$noncn_count"
    done
  fi
done
echo "=== End Debug ==="

# 对比CN和!CN分组
compare_cn_pairs "srs/json/ai-cn.json" "srs/json/ai-noncn.json" "srs/json/same/ai-same.json"
compare_cn_pairs "srs/json/games-cn.json" "srs/json/games-noncn.json" "srs/json/same/games-same.json"
compare_cn_pairs "srs/json/network-cn.json" "srs/json/network-noncn.json" "srs/json/same/network-same.json"

# 优化相同部分的JSON文件
for same_file in srs/json/same/*.json; do
  if [ -f "$same_file" ]; then
    echo "Found same file: $same_file"
    optimize_json_file "$same_file"
  else
    echo "No same files found or directory doesn't exist"
  fi
done

echo "Operation A completed!"

# URL定义阶段
ads_urls=(
  "srs/json/ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-acfun-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-acfun-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-acfun@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-adcolony-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-adcolony-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-adjust-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-adjust-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-adobe-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-adobe-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-adobe@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-alibaba-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-alibaba-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-alibaba@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-amazon-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-amazon-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-amazon@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-apple-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-apple-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-apple@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-applovin-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-applovin-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-atom-data-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-atom-data-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-baidu-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-baidu-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-baidu@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bytedance-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bytedance-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bytedance@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ads-all.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ads-ir.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ai-!cn@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ai-chat-!cn@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-cas@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-communication@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-companies@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-dev@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ecommerce@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-entertainment-cn@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-entertainment@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-httpdns-cn@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-media-cn@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-porn@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-!cn@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-cn@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-speedtest@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-clearbitjs-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-clearbitjs-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-disney@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-dmm-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-dmm-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-dmm@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-duolingo-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-duolingo-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-duolingo@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-emogi-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-emogi-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-facebook-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-facebook-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-flurry-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-flurry-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-fqnovel@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-gamersky@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-google-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-google-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-google@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-growingio-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-growingio-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hetzner@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hiido-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hiido-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hotjar-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hotjar-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hunantv-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hunantv-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hunantv@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-inner-active-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-inner-active-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-instagram-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-instagram-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-instagram@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-iqiyi-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-iqiyi-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-iqiyi@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-jd-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-jd-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-jd@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-kuaishou-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-kuaishou-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-kuaishou@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-kugou-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-kugou-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-kugou@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-le@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-leanplum-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-leanplum-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-letv-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-letv-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-meta-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-meta-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-meta@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-microsoft@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mixpanel-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mixpanel-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mopub-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mopub-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mxplayer-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mxplayer-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-netease-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-netease-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-netease@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-newrelic-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-newrelic-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ogury-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ogury-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-onesignal-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-onesignal-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ookla-speedtest-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ookla-speedtest-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ookla-speedtest@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-openai@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-openx-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-openx-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-pikpak@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-pixiv@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-pocoiq-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-pocoiq-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-pubmatic-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-pubmatic-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-pubmatic@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-qihoo360-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-qihoo360-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-qihoo360@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-samsung@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-segment-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-segment-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sensorsdata-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sensorsdata-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sina-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sina-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sina@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-snap@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sohu-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sohu-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sohu@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-speedtest@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-spotify-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-spotify-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-supersonic-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-supersonic-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tagtic-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tagtic-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tappx-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tappx-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-television-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-television-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tencent-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tencent-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tencent@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-uberads-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-uberads-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-umeng-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-umeng-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-umeng@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-unity-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-unity-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-unity@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-verizon@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-whatsapp-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-whatsapp-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-whatsapp@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-wteam-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-wteam-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-xhamster-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-xhamster-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-xhamster@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-xiaomi-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-xiaomi-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-xiaomi@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ximalaya-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ximalaya-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-yahoo-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-yahoo-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-yahoo@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-youku-ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-youku-ads@ads.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-win-spy.json"
)

games_cn_urls=(
  "srs/json/games-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bilibili-game@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bluepoch-games@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-gamersky.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-herogame.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-kurogames@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-epicgames@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tencent-games@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-game-accelerator-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-game-platforms-download@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-!cn@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-cn@cn.json"
  "srs/json/geosite-category-games-cn@cn2.json"
)

games_noncn_urls=(
  "srs/json/games-noncn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-cygames.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-steam.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-2kgames.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tencent-games@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-wbgames.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-cn@!cn.json"
  "srs/json/geosite-category-games-!cn@!cn.json"
  "srs/json/game-platforms-download@!cn.json"
  "srs/json/geosite-epicgames@!cn.json"
)

ai_cn_urls=(
  "srs/json/ai-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-jetbrains@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-deepseek.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-aixcoder.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-apple-intelligence.json"
  "srs/json/doubao@cn.json"
  "srs/json/geosite-category-ai-cn@cn.json"
)

ai_noncn_urls=(
  "srs/json/ai-noncn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ai-!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ai-chat-!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ai-cn@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-openai.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-xai.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-google-gemini.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-meta.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-perplexity.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-poe.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-anthropic.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-jetbrains-ai.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-doubao@!cn.json"
  "srs/json/jetbrains@!cn.json"
)

media_urls=(
  "srs/json/media.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-netflix.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-netflix.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-disney.json"
)

network_cn_urls=(
  "srs/json/network-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-china-list.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-geolocation-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-geolocation-cn@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-acer@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-adidas@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-adobe@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-aerogard@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-airwick@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-akamai@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-amazon@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-amd@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-amp@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-apple-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-apple-dev@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-apple-pki@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-apple@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-asus@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-att@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-aws-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-aws-cn@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-aws@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-azure@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-beats@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bestbuy@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bilibili@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bing@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bluearchive@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bluepoch@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bmw@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-booking@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bridgestone@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-broadcom@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-calgoncarbon@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-canon@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-antivirus@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-automobile-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-blog-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-cas@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-collaborate-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-companies@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-cryptocurrency@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-dev-cn@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-dev@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-documents-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ecommerce@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-education-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-electronic-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-enhance-gaming@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-enterprise-query-platform-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-entertainment-cn@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-entertainment@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-finance@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-food-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-hospital-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-httpdns-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-logistics-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-media-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-media@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-mooc-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-netdisk-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-network-security-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ntp-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ntp-cn@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ntp@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-number-verification-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-outsource-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-remote-control@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-scholar-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-securities-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-!cn@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-speedtest@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-tech-media@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-wiki-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-cisco@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-clearasil@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-cloudflare-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-cloudflare-cn@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-cloudflare@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-dell@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-dettol@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-digicert@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-duolingo@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-durex@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ebay@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-entrust@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-eset@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-familymart@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-farfetch@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-fflogs@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-finish@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-firebase@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-gigabyte@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-globalsign@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-gog@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-google-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-google-play@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-google-trust-services@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-google@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-gucci@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hketgroup@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hm@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hp@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-hsbc-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-huawei-dev@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-huawei@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-icloud@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ifast@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ikea@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-intel@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-itunes@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-kaspersky@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-kechuang@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-kindle@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-linkedin@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-lysol@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mapbox@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mastercard@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mcdonalds@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-meadjohnson@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-microsoft-dev@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-microsoft-pki@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-microsoft@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mihoyo-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mihoyo-cn@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mihoyo@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-miniso@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-mortein@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-movefree@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-msn@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-muji@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-nike@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-nintendo@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-nurofen@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-nvidia@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-okaapps@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-okx@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-openjsfoundation@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-oreilly@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-panasonic@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-paypal@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-pearson@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-primevideo@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-qnap@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-qualcomm@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-razer@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-rb@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-reabble@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-riot@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-samsung@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sectigo@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-shopee@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sky@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sslcom@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-st@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-starbucks@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-steam@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-strepsils@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-swift@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-synology@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-teamviewer@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tencent-dev@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tencent@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tesla@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-test-ipv6@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-thelinuxfoundation@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-thetype@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tld-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tvb@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ubiquiti@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ubisoft@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-vanish@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-veet@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-verizon@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-visa@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-vmware@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-volvo@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-walmart@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-webex@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-westerndigital@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-woolite@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-xbox@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-yahoo@cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-youtube@cn.json"
  "srs/json/geosite-category-social-media-cn@cn.json"
  "srs/json/geosite-category-bank-cn@cn.json"
  "srs/json/geosite-category-dev-cn@cn2.json"
  "srs/json/geosite-category-entertainment-cn@cn2.json"
)

network_noncn_urls=(
  "srs/json/network-noncn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-facebook.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-telegram.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-twitter.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-github.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-gitlab.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-geolocation-!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-gfw.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-win-extra.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-win-update.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-alibaba@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-alibabacloud@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-aliyun@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bilibili@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-boc@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-bytedance@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-bank-cn@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-browser-!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-companies@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-dev-cn@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-entertainment-cn@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-entertainment@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-pt@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-scholar-!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-cn@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-speedtest@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ccb@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-chinamobile@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-chinatelecom@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-chinaunicom@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-citic@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-cmb@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ctexcel@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ctrip@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-deepin@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-dewu@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-didi@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-eastmoney@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-google@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-googlefcm@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-huawei@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-huaweicloud@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-icbc@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-ipip@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-iqiyi@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-jd@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-oneplus@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-oppo@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-pingan@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-qcloud@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-sina@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tencent@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tiktok@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-tld-!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-trae@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-vivo@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-xiaomi@!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-zte@!cn.json"
  "srs/json/geosite-category-social-media-!cn@!cn.json"
)

cdn_urls=(
  "srs/json/cdn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-cloudflare.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-cloudfront.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-fastly.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-google.json"
)

hkmotw_urls=(
  "srs/json/hkmotw.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-hk.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-mo.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-tw.json"
)

private_urls=(
  "srs/json/private.json"
  "https://raw.githubusercontent.com/paka666/rules/main/srs/json/geoip-private.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-private.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-private.json"
)

validate_and_fix_json() {
  local file="$1"
  local group_name="$2"

  if [ ! -f "$file" ] || [ ! -s "$file" ]; then
    echo "  File not found or empty: $file"
    return 1
  fi

  if ! jq empty "$file" >/dev/null 2>&1; then
    echo "  Invalid JSON in $file, attempting to fix..."

    local temp_file="${file}.fixed"

    if jq '.' "$file" > "$temp_file" 2>/dev/null; then
      mv "$temp_file" "$file"
      echo "  Fixed JSON using jq"
      return 0
    fi

    if jq 'if type == "array" then {version: 1, rules: .} else . end' "$file" > "$temp_file" 2>/dev/null; then
      mv "$temp_file" "$file"
      echo "  Added version to rules array"
      return 0
    fi

    if jq 'if .rules and (.version | not) then .version = 1 else . end' "$file" > "$temp_file" 2>/dev/null; then
      mv "$temp_file" "$file"
      echo "  Added version field"
      return 0
    fi

    echo "  Could not fix JSON: $file"
    rm -f "$file" "$temp_file"
    return 1
  fi

  if ! jq 'has("version")' "$file" 2>/dev/null | grep -q true; then
    echo "  Adding version field to $file"
    jq '.version = 1' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
  fi

  return 0
}

# 合并组函数
merge_group() {
  local GROUP_NAME=$1
  shift
  local URLS=("$@")
  local LOCAL_JSON_FILE="${URLS[0]}"
  local OUTPUT_SRS_FILE="srs/${GROUP_NAME}.srs"
  local TIMESTAMP
  TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

  rm -f temp/input-"$GROUP_NAME"-*.json
  rm -f "$OUTPUT_SRS_FILE"

  echo "Starting merge for group: $GROUP_NAME"

  local i=1
  local pids=()
  for url in "${URLS[@]}"; do
    if [ -z "$url" ]; then
      continue
    fi

    local current_i=$i
    (
      local file_index=$current_i
      local output_file="temp/input-$GROUP_NAME-$file_index.json"

      if [[ "$url" == /* ]] || [[ "$url" == ./* ]] || [[ "$url" == srs/* ]]; then
        if [ -f "$url" ] && [ -s "$url" ]; then
          cp "$url" "$output_file"
          echo "Copied local file: $url"
        else
          echo "Warning: local file $url not found or empty"
          rm -f "$output_file"
        fi
      else
        echo "Downloading: $url"
        if wget -q --timeout=180 --tries=3 "$url" -O "$output_file"; then
          echo "  Downloaded: $url"
        else
          echo "Warning: failed to download $url (group $GROUP_NAME)"
          rm -f "$output_file"
        fi
      fi

      if [ -f "$output_file" ]; then
        if ! validate_and_fix_json "$output_file" "$GROUP_NAME"; then
          echo "  Removing invalid file: $output_file"
          rm -f "$output_file"
        fi
      fi
    ) &
    pids+=($!)

    ((i++))
  done

  if [ ${#pids[@]} -gt 0 ]; then
    echo "Waiting for ${#pids[@]} downloads for group $GROUP_NAME..."
    wait "${pids[@]}" 2>/dev/null
    echo "Downloads for $GROUP_NAME finished."
  fi

  shopt -s nullglob
  local inputs=(temp/input-"$GROUP_NAME"-*.json)
  shopt -u nullglob

  if [ "${#inputs[@]}" -eq 0 ]; then
    echo "Error: no input files available for group $GROUP_NAME — skipping merge."
    return 1
  fi

  echo "Found ${#inputs[@]} valid input files for group $GROUP_NAME"

  local valid_inputs=()
  for input_file in "${inputs[@]}"; do
    if validate_and_fix_json "$input_file" "$GROUP_NAME"; then
      valid_inputs+=("$input_file")
    else
      echo "  Skipping invalid file: $input_file"
    fi
  done

  if [ ${#valid_inputs[@]} -eq 0 ]; then
    echo "Error: no valid input files after validation for group $GROUP_NAME"
    return 1
  fi

  echo "Using ${#valid_inputs[@]} valid files for merging"

  local merged_tmp="temp/merged-$GROUP_NAME.json"
  local config_flags=()
  for input_file in "${valid_inputs[@]}"; do
    config_flags+=("-c" "$input_file")
  done

  echo "Merging ${#valid_inputs[@]} files for group $GROUP_NAME..."
  if ! sing-box rule-set merge "$merged_tmp" "${config_flags[@]}"; then
    echo "Error: Failed to merge JSON files for $GROUP_NAME"
    return 1
  fi

  # 在编译SRS前进行优化
  echo "Optimizing merged JSON before compilation..."
  optimize_json_file "$merged_tmp"

  if ! validate_and_fix_json "$merged_tmp" "$GROUP_NAME"; then
    echo "Error: Merged file is invalid"
    return 1
  fi

  local json_backup="srs/json/${GROUP_NAME}.json.bak.${TIMESTAMP}"
  if [ -f "$LOCAL_JSON_FILE" ]; then
    cp -a "$LOCAL_JSON_FILE" "$json_backup"
  fi

  mkdir -p "$(dirname "$LOCAL_JSON_FILE")"
  mv -f "$merged_tmp" "$LOCAL_JSON_FILE"
  echo "Saved merged JSON to: $LOCAL_JSON_FILE (backup: $json_backup)"

  echo "Compiling SRS file for $GROUP_NAME..."
  if sing-box rule-set compile "$LOCAL_JSON_FILE" -o "$OUTPUT_SRS_FILE"; then
    echo "Successfully compiled: $OUTPUT_SRS_FILE"
  else
    echo "Error: Failed to compile SRS for $GROUP_NAME"

    if [ -f "$json_backup" ]; then
      cp -a "$json_backup" "$LOCAL_JSON_FILE"
      echo "Restored JSON from backup: $json_backup"
    fi
    return 1
  fi

  rm -f temp/input-"$GROUP_NAME"-*.json
  echo "Completed group $GROUP_NAME -> JSON: $LOCAL_JSON_FILE, SRS: $OUTPUT_SRS_FILE"
}

echo "Starting merge process..."
merge_group "ads" "${ads_urls[@]}"
merge_group "games-cn" "${games_cn_urls[@]}"
merge_group "games-noncn" "${games_noncn_urls[@]}"
merge_group "ai-cn" "${ai_cn_urls[@]}"
merge_group "ai-noncn" "${ai_noncn_urls[@]}"
merge_group "media" "${media_urls[@]}"
merge_group "network-cn" "${network_cn_urls[@]}"
merge_group "network-noncn" "${network_noncn_urls[@]}"
merge_group "cdn" "${cdn_urls[@]}"
merge_group "hkmotw" "${hkmotw_urls[@]}"
merge_group "private" "${private_urls[@]}"

# 清理旧的备份文件（保留最近3个）
cleanup_old_backups() {
    echo "Cleaning up old backup files..."
    find srs/json -name "*.bak.*" -type f | sort -r | tail -n +4 | xargs rm -f 2>/dev/null || true
    # 清理临时文件
    rm -f temp/ip_cidr_*.json
}
cleanup_old_backups

# 添加文件大小统计函数
print_size_stats() {
  echo "=== File Size Statistics ==="
  for json_file in srs/json/*.json; do
    if [ -f "$json_file" ] && [[ "$json_file" != *.bak.* ]]; then
      local size=$(stat -c %s "$json_file" 2>/dev/null || echo 0)
      local name=$(basename "$json_file")
      printf "  %-40s: %10d bytes\n" "$name" "$size"
    fi
  done

  echo "=== SRS File Statistics ==="
  for srs_file in srs/*.srs; do
    if [ -f "$srs_file" ]; then
      local size=$(stat -c %s "$srs_file" 2>/dev/null || echo 0)
      local name=$(basename "$srs_file")
      printf "  %-40s: %10d bytes\n" "$name" "$size"
    fi
  done
}

echo "All groups processed successfully!"
echo "JSON files are in: srs/json/"
echo "SRS files are in: srs/"
echo "Common parts are in: srs/json/same/"
print_size_stats

# git config --global user.name "GitHub Actions"
# git config --global user.email "actions@github.com"
# git add srs/*.srs srs/json/*.json srs/json/same/*.json
# git commit -m "Daily merge update: $(date +%Y-%m-%d)" || echo "No changes to commit"
# git push origin main
