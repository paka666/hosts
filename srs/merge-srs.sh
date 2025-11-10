#!/usr/bin/env bash
#
# 这是一个用于合并、优化和编译 sing-box 规则集的完整脚本。
# 它解决了以下问题：
# 1. 合并：使用 'jq' 将所有规则源合并为 *一个* 规则对象，而不是 'sing-box merge' 的数组连接。
# 2. 优化：执行多阶段优化，包括 domain/domain_suffix 的交叉互补。
# 3. IP合并：使用 Python 'ipaddress' 模块合并 IPv4 和 IPv6 CIDR。
# 4. 预处理：在主合并前，执行 CN/!CN 规则的减法和对比。
# 5. 格式处理：重构了验证逻辑，可正确处理多种 "classical" 规则格式。
#

# --- 脚本设置 ---
# set -e: 脚本中任意命令执行失败则立即退出
# set -u: 尝试使用未定义的变量时报错
# set -o pipefail: 管道中的任一命令失败，整个管道都算失败
set -euo pipefail

# --- 创建必要目录 ---
mkdir -p temp srs srs/json srs/json/same

# ========== 1. 依赖检查 ==========
check_dependencies() {
  local deps=("jq" "curl" "sing-box" "python3")
  local missing=()

  for dep in "${deps[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      missing+=("$dep")
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
    echo "错误: 缺少依赖: ${missing[*]}"
    echo "请先安装这些依赖"
    exit 1
  fi

  # 检查Python ipaddress模块
  if ! python3 -c "import ipaddress" >/dev/null 2>&1; then
    echo "错误: 需要Python 'ipaddress' 模块"
    exit 1
  fi
}

# ========== 2. JSON 验证与修复 (已重构) ==========
# 此函数用于在下载/复制后立刻标准化所有规则文件
# 确保所有文件都符合 { "version": 1, "rules": [ ...对象... ] } 格式
validate_and_fix_json() {
  local file="$1"
  # local group_name="$2" # group_name 未在此函数中使用
  local temp_file="${file}.tmp"

  if [ ! -f "$file" ] || [ ! -s "$file" ]; then
    echo "  验证失败: 文件不存在或为空: $file"
    return 1
  fi

  # 1. 检查是否是 'sing-box' 格式 (有 .version 和 .rules)
  if jq -e '.version and .rules' "$file" >/dev/null 2>&1; then
    # 1a. 检查 .rules 是否是 array-of-strings-of-json (内嵌JSON字符串)
    if jq -e '.rules[0] | type == "string" and startswith("{")' "$file" >/dev/null 2>&1; then
      echo "  修复 $file: 解析 .rules 内部的 JSON 字符串..."
      jq '.rules |= map(fromjson)' "$file" > "$temp_file" && mv "$temp_file" "$file"
    # 1b. 检查 .rules 是否是 array-of-strings (非JSON，经典domain列表)
    elif jq -e '.rules[0] | type == "string" and (startswith("{") | not)' "$file" >/dev/null 2>&1; then
      echo "  修复 $file: 将 .rules 字符串数组包装为 domain 对象..."
      jq '.rules |= [{domain: .}]' "$file" > "$temp_file" && mv "$temp_file" "$file"
    fi
    return 0 # 已经是有效或已修复的 sing-box 格式
  fi

  # 2. 检查是否是 'classical' 根数组
  if jq -e 'type == "array"' "$file" >/dev/null 2>&1; then
    echo "  修复 $file: 转换 'classical' 根数组格式..."
    # 2a. 检查是否是 array-of-strings-of-json
    if jq -e '.[0] | type == "string" and startswith("{")' "$file" >/dev/null 2>&1; then
      jq '{version: 1, rules: map(fromjson)}' "$file" > "$temp_file" && mv "$temp_file" "$file"
    # 2b. 检查是否是 array-of-strings (non-json)
    elif jq -e '.[0] | type == "string" and (startswith("{") | not)' "$file" >/dev/null 2>&1; then
      jq '{version: 1, rules: [{domain: .}]}' "$file" > "$temp_file" && mv "$temp_file" "$file"
    # 2c. 检查是否是 array-of-objects (已是 .rules 内容)
    elif jq -e '.[0] | type == "object"' "$file" >/dev/null 2>&1; then
        jq '{version: 1, rules: .}' "$file" > "$temp_file" && mv "$temp_file" "$file"
    # 2d. 空数组
    else
        jq '{version: 1, rules: []}' "$file" > "$temp_file" && mv "$temp_file" "$file"
    fi
    return 0
  fi

  # 3. 检查是否是 'classical' 根对象 (缺少 version/rules)
  if jq -e 'type == "object" and (.rules | not)' "$file" >/dev/null 2>&1; then
    echo "  修复 $file: 将根对象包装到 .rules 数组中..."
    jq '{version: 1, rules: [.]}' "$file" > "$temp_file" && mv "$temp_file" "$file"
    return 0
  fi

  # 4. 无法识别或修复
  echo "  错误: 无法修复或识别 $file 的JSON结构"
  rm -f "$file"
  return 1
}

# ========== 3. 核心优化函数 (已重构) ==========
# 此函数将合并后的 JSON 文件作为输入，执行所有优化
optimize_json_file() {
  local json_file="$1"
  local temp_file="${json_file}.tmp"
  local before_size=$(stat -c %s "$json_file" 2>/dev/null || echo 0)

  echo "优化JSON文件: $json_file (大小: $before_size 字节)"

  if [ ! -f "$json_file" ] || ! jq empty "$json_file" >/dev/null 2>&1; then
    echo "  文件不存在或JSON无效，跳过"
    return 1
  fi
  
  # 步骤0: 检查未知字段 (来自您的要求)
  # 确保 .rules[0] 存在
  if jq -e '.rules[0]' "$json_file" >/dev/null 2>&1; then
    local unknown_keys=$(jq -r '
      .rules[0] | 
      keys_unsorted | 
      map(select(. != "domain" and . != "domain_suffix" and . != "domain_keyword" and . != "domain_regex" and . != "ip_cidr")) | 
      join(", ")
    ' "$json_file")
    
    if [ -n "$unknown_keys" ]; then
      echo "错误: 在 $json_file 中发现未知字段: [$unknown_keys]"
      echo "请更新 optimize_json_file 函数以处理这些字段，脚本中止。"
      exit 1
    fi
  else
    echo "  警告: $json_file 的 .rules 数组为空，跳过优化。"
    return 0
  fi

  # 步骤1：标准化字段 (去重、排序、规范化)
  jq '
    def ensure_array: 
      if . == null then [] 
      elif type == "array" then map(tostring) 
      else [tostring] end;
    def process_domain: 
      ensure_array | map(if startswith(".") then .[1:] else . end) | unique | sort;
    def process_domain_suffix: 
      ensure_array | map(if startswith(".") then . else "." + . end) | unique | sort;
    def process_other: 
      ensure_array | unique | sort;

    .rules[0] |= (
      . as $rule |
      {
        domain: (($rule.domain // []) | process_domain),
        domain_suffix: (($rule.domain_suffix // []) | process_domain_suffix),
        domain_keyword: (($rule.domain_keyword // []) | process_other),
        domain_regex: (($rule.domain_regex // []) | process_other),
        ip_cidr: (($rule.ip_cidr // []) | process_other)
      }
    )
  ' "$json_file" > "$temp_file" && mv "$temp_file" "$json_file"

  # 步骤2：交叉链接 domain 和 domain_suffix
  jq '
    if .rules and (.rules | length > 0) then
      .rules[0] |= (
        . as $rule |
        {
          domain_suffix: (($rule.domain_suffix // []) + ($rule.domain | map("." + .)) | unique | sort),
          domain: (($rule.domain // []) + ($rule.domain_suffix | map(if startswith(".") then .[1:] else . end)) | unique | sort),
          domain_keyword: ($rule.domain_keyword // []),
          domain_regex: ($rule.domain_regex // []),
          ip_cidr: ($rule.ip_cidr // [])
        }
      )
    else . end
  ' "$json_file" > "$temp_file" && mv "$temp_file" "$json_file"

  # 步骤3：合并 ip_cidr
  local ip_cidr_json=$(jq '.rules[0].ip_cidr // []' "$json_file")

  if [ "$ip_cidr_json" != "[]" ] && [ "$ip_cidr_json" != "null" ]; then
    local merged_ip_cidr

    merged_ip_cidr=$(echo "$ip_cidr_json" | python3 -c "
import ipaddress
import json
import sys
try:
    cidrs = json.loads(sys.stdin.read())
    if not cidrs:
        print('[]')
    else:
        ipv4_nets = []
        ipv6_nets = []
        for c in cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
                if net.version == 4: ipv4_nets.append(net)
                else: ipv6_nets.append(net)
            except ValueError as e:
                print(f'警告: 跳过无效CIDR {c}: {e}', file=sys.stderr)

        merged_v4 = sorted(ipaddress.collapse_addresses(ipv4_nets))
        merged_v6 = sorted(ipaddress.collapse_addresses(ipv6_nets))

        merged = [str(n) for n in merged_v4] + [str(n) for n in merged_v6]
        print(json.dumps(merged))
except Exception as e:
    print('[]') 
    print(f'IP CIDR 合并错误: {e}', file=sys.stderr)
" 2> temp/ip_merge_log.txt)

    # 更新回JSON
    jq --argjson cidrs "$merged_ip_cidr" '.rules[0].ip_cidr = $cidrs' \
      "$json_file" > "$temp_file" && mv "$temp_file" "$json_file"
  fi

  local after_size=$(stat -c %s "$json_file" 2>/dev/null || echo 0)
  local reduction=$((before_size - after_size))
  echo "  优化完成 (压缩: $reduction 字节)"
}

# ========== 4. 预处理 (规则减法) ==========
preprocess_ruleset() {
  local base_url="$1"
  local exclude_url="$2"
  local output_file="$3"
  # local output_type="$4" # output_type 未在此函数中使用

  echo "预处理: $base_url - $exclude_url -> $output_file"
  local base_temp="temp/base_$(basename "$output_file").json"
  local exclude_temp="temp/exclude_$(basename "$output_file").json"

  # 下载 (使用 curl 和重试)
  local retry=0
  while [ $retry -lt 3 ]; do
    if curl -s --fail --connect-timeout 180 --max-time 180 -o "$base_temp" "$base_url"; then
      break
    fi
    echo "  下载 $base_url 失败，重试 $((retry+1))/3"
    retry=$((retry+1))
    sleep 5
  done
  if [ $retry -eq 3 ]; then
    echo "  下载 $base_url 失败，跳过"
    return 1
  fi

  # 验证下载的文件
  validate_and_fix_json "$base_temp" "preprocess_base" || (rm -f "$base_temp"; return 1)

  retry=0
  while [ $retry -lt 3 ]; do
    if curl -s --fail --connect-timeout 180 --max-time 180 -o "$exclude_temp" "$exclude_url"; then
      break
    fi
    echo "  下载 $exclude_url 失败，重试 $((retry+1))/3"
    retry=$((retry+1))
    sleep 5
  done
  if [ $retry -eq 3 ]; then
    echo "  下载 $exclude_url 失败，跳过"
    rm -f "$base_temp"
    return 1
  fi

  # 验证下载的文件
  validate_and_fix_json "$exclude_temp" "preprocess_exclude" || (rm -f "$base_temp" "$exclude_temp"; return 1)

  # 移除排除规则
  jq --slurpfile exclude "$exclude_temp" '
    # 将 $base_rules 和 $exclude_rules 确保为单个对象
    .rules[0] as $base_rule |
    $exclude[0].rules[0] as $exclude_rule |
    {
      version: 1,
      rules: [
        {
          domain:         ($base_rule.domain // [])         - ($exclude_rule.domain // []),
          domain_suffix:  ($base_rule.domain_suffix // [])  - ($exclude_rule.domain_suffix // []),
          domain_keyword: ($base_rule.domain_keyword // []) - ($exclude_rule.domain_keyword // []),
          domain_regex:   ($base_rule.domain_regex // [])   - ($exclude_rule.domain_regex // []),
          ip_cidr:        ($base_rule.ip_cidr // [])        - ($exclude_rule.ip_cidr // [])
        }
      ]
    }
  ' "$base_temp" > "$output_file"

  rm -f "$base_temp" "$exclude_temp"

  if jq empty "$output_file" >/dev/null 2>&1; then
    echo "  成功生成: $output_file"
  else
    echo "  错误: 生成的JSON无效 $output_file"
    rm -f "$output_file"
    return 1
  fi
}

# ========== 5. CN/!CN 对比 (规则提取) ==========
compare_cn_pairs() {
  local cn_file="$1"
  local noncn_file="$2"
  local output_file="$3"

  echo "对比CN配对: $cn_file vs $noncn_file"

  if [ ! -f "$cn_file" ] || [ ! -f "$noncn_file" ]; then
    echo "  文件不存在，跳过"
    return 0
  fi

  if ! jq empty "$cn_file" >/dev/null 2>&1 || ! jq empty "$noncn_file" >/dev/null 2>&1; then
    echo "  JSON无效，跳过"
    return 0
  fi

  # 找出共同部分
  jq -n --slurpfile cn "$cn_file" --slurpfile noncn "$noncn_file" '
    def find_common($a; $b):
      if $a and $b then
        $a | map(select(. as $item | $b | index($item)))
      else [] end;

    # 安全地获取字段, 确保 .rules[0] 存在
    def get_field($file; $field):
      if $file[0].rules and ($file[0].rules | length > 0) and 
         $file[0].rules[0][$field] then
        $file[0].rules[0][$field]
      else [] end;

    {
      version: 1,
      rules: [{
        domain: find_common(get_field($cn; "domain"); get_field($noncn; "domain")),
        domain_suffix: find_common(get_field($cn; "domain_suffix"); get_field($noncn; "domain_suffix")),
        domain_keyword: find_common(get_field($cn; "domain_keyword"); get_field($noncn; "domain_keyword")),
        domain_regex: find_common(get_field($cn; "domain_regex"); get_field($noncn; "domain_regex")),
        ip_cidr: find_common(get_field($cn; "ip_cidr"); get_field($noncn; "ip_cidr"))
      }]
    }
  ' > "$output_file"

  # 检查是否为空
  local is_empty=$(jq '[.rules[0] | to_entries[] | .value | length] | add == 0' "$output_file")

  if [ "$is_empty" = "true" ]; then
    echo "  没有共同部分"
    rm -f "$output_file"
    return 0
  fi

  # 从原文件移除共同部分
  for file in "$cn_file" "$noncn_file"; do
    local temp_file="${file}.tmp"
    jq --slurpfile common "$output_file" '
      def remove_common($arr; $common_arr):
        if $arr and $common_arr then $arr - $common_arr else $arr end;

      if .rules and (.rules | length > 0) then
        .rules[0] |= {
          domain: remove_common(.domain; $common[0].rules[0].domain),
          domain_suffix: remove_common(.domain_suffix; $common[0].rules[0].domain_suffix),
          domain_keyword: remove_common(.domain_keyword; $common[0].rules[0].domain_keyword),
          domain_regex: remove_common(.domain_regex; $common[0].rules[0].domain_regex),
          ip_cidr: remove_common(.ip_cidr; $common[0].rules[0].ip_cidr)
        }
      else . end
    ' "$file" > "$temp_file" && mv "$temp_file" "$file"
  done

  echo "  共同部分已保存到: $output_file"
}

# ========== 6. 主合并函数 (核心修复) ==========
merge_group() {
  local GROUP_NAME=$1
  shift
  local URLS=("$@")

  local LOCAL_JSON_FILE="srs/json/${GROUP_NAME}.json"
  local OUTPUT_SRS_FILE="srs/${GROUP_NAME}.srs"
  local TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

  rm -f temp/input-"$GROUP_NAME"-*.json "$OUTPUT_SRS_FILE"

  echo "=== 开始合并组: $GROUP_NAME ==="

  # --- 步骤 1: 并行下载/复制 ---
  local i=1
  local pids=()
  for url in "${URLS[@]}"; do
    [ -z "$url" ] && continue
    local current_i=$i
    (
      local output_file="temp/input-$GROUP_NAME-$current_i.json"
      # 本地文件
      if [[ "$url" == /* ]] || [[ "$url" == ./* ]] || [[ "$url" == srs/* ]]; then
        if [ -f "$url" ] && [ -s "$url" ]; then
          cp "$url" "$output_file"
          echo "  复制: $url"
        fi
      # 远程文件
      else
        local retry=0
        while [ $retry -lt 3 ]; do
          if curl -s --fail --connect-timeout 60 --max-time 60 -o "$output_file" "$url"; then
            echo "  下载: $url"
            break
          fi
          # 下载失败，增加指数退避
          local sleep_time=$((5 * (2**retry)))
          echo "  下载 $url 失败，重试 $((retry+1))/3 (等待 ${sleep_time}s)..."
          retry=$((retry+1))
          sleep "$sleep_time"
        done
        if [ $retry -eq 3 ]; then
          echo "  失败: $url (已放弃)"
          rm -f "$output_file"
        fi
      fi
      # 立刻验证
      if [ -f "$output_file" ]; then
        validate_and_fix_json "$output_file" "$GROUP_NAME" || rm -f "$output_file"
      fi
    ) &
    pids+=($!)
    ((i++))
  done
  [ ${#pids[@]} -gt 0 ] && wait "${pids[@]}" 2>/dev/null
  echo "  下载/复制 完成"

  # --- 步骤 2: 收集输入文件 ---
  shopt -s nullglob
  local inputs=(temp/input-"$GROUP_NAME"-*.json)
  shopt -u nullglob

  if [ "${#inputs[@]}" -eq 0 ]; then
    echo "  错误: $GROUP_NAME 组没有可用的输入文件"
    return 1
  fi

  echo "  找到 ${#inputs[@]} 个有效文件"
  local merged_tmp="temp/merged-$GROUP_NAME.json"

  # --- 步骤 3: !! 核心修复: 使用 JQ 合并 !! ---
  # 不使用 'sing-box rule-set merge'
  # 而是用 jq -s (slurp) 手动合并所有规则到 *一个* 对象
  echo "  使用 jq 合并所有规则..."
  if ! jq -s '
    # 1. 将所有文件的 .rules 数组拍平为一个数组
    #    (validate_and_fix_json 确保了 .rules 总是存在且为 [ ...对象... ] 格式)
    [ map(.rules // []) | flatten ] |

    # 2. 将这个包含所有规则对象的数组归并（reduce）成一个单一的对象
    reduce .[] as $rule_obj (
      {}; # 初始值：一个空对象
      # 累加每个字段的数组 (确保 nulls 变为空数组)
      .domain        += ($rule_obj.domain // []) |
      .domain_suffix += ($rule_obj.domain_suffix // []) |
      .domain_keyword += ($rule_obj.domain_keyword // []) |
      .domain_regex  += ($rule_obj.domain_regex // []) |
      .ip_cidr       += ($rule_obj.ip_cidr // [])
    ) |

    # 3. 将合并后的单一对象包装回 sing-box 格式
    {
      version: 1,
      rules: [ . ]
    }
  ' "${inputs[@]}" > "$merged_tmp"; then
    echo "  错误: 使用 jq 合并JSON失败"
    rm -f "$merged_tmp"
    return 1
  fi

  # --- 步骤 4: 优化合并后的文件 ---
  # (现在 $merged_tmp 已经是您想要的 [ { ... } ] 结构了)
  optimize_json_file "$merged_tmp"

  # --- 步骤 5: 备份和保存 ---
  if [ -f "$LOCAL_JSON_FILE" ]; then
    cp -a "$LOCAL_JSON_FILE" "srs/json/${GROUP_NAME}.json.bak.${TIMESTAMP}"
  fi
  mkdir -p "$(dirname "$LOCAL_JSON_FILE")"
  mv -f "$merged_tmp" "$LOCAL_JSON_FILE"

  # --- 步骤 6: 编译 SRS ---
  if sing-box rule-set compile "$LOCAL_JSON_FILE" -o "$OUTPUT_SRS_FILE" 2>/dev/null; then
    echo "  成功编译: $OUTPUT_SRS_FILE"
  else
    echo "  错误: 编译SRS失败 ($GROUP_NAME)"
    # 编译失败时回滚
    if [ -f "srs/json/${GROUP_NAME}.json.bak.${TIMESTAMP}" ]; then
      mv "srs/json/${GROUP_NAME}.json.bak.${TIMESTAMP}" "$LOCAL_JSON_FILE"
      echo "  已从备份回滚 $LOCAL_JSON_FILE"
    fi
    return 1
  fi

  # --- 步骤 7: 清理 ---
  rm -f temp/input-"$GROUP_NAME"-*.json
  echo "  组 $GROUP_NAME 处理完毕"

  # --- 步骤 8: 增量更新 'same' 文件 (来自您的要求) ---
  local same_temp_file="temp/same-temp-${GROUP_NAME}.json"
  case "$GROUP_NAME" in
    "ai-cn"|"ai-noncn")
      compare_cn_pairs "srs/json/ai-cn.json" "srs/json/ai-noncn.json" "$same_temp_file"
      if [ -f "$same_temp_file" ]; then
        if [ -f "srs/json/same/ai-same.json" ]; then
          jq -s '.[0].rules[0] as $old | .[1].rules[0] as $new | {version: 1, rules: [{domain: ($old.domain + $new.domain | unique | sort), domain_suffix: ($old.domain_suffix + $new.domain_suffix | unique | sort), domain_keyword: ($old.domain_keyword + $new.domain_keyword | unique | sort), domain_regex: ($old.domain_regex + $new.domain_regex | unique | sort), ip_cidr: ($old.ip_cidr + $new.ip_cidr | unique | sort)}]}' "srs/json/same/ai-same.json" "$same_temp_file" > "srs/json/same/ai-same.json.tmp" && mv "srs/json/same/ai-same.json.tmp" "srs/json/same/ai-same.json"
          echo "  增量更新 ai-same.json"
        else
          mv "$same_temp_file" "srs/json/same/ai-same.json"
        fi
        optimize_json_file "srs/json/same/ai-same.json"
      fi
      ;;
    "games-cn"|"games-noncn")
      compare_cn_pairs "srs/json/games-cn.json" "srs/json/games-noncn.json" "$same_temp_file"
      if [ -f "$same_temp_file" ]; then
        if [ -f "srs/json/same/games-same.json" ]; then
          jq -s '.[0].rules[0] as $old | .[1].rules[0] as $new | {version: 1, rules: [{domain: ($old.domain + $new.domain | unique | sort), domain_suffix: ($old.domain_suffix + $new.domain_suffix | unique | sort), domain_keyword: ($old.domain_keyword + $new.domain_keyword | unique | sort), domain_regex: ($old.domain_regex + $new.domain_regex | unique | sort), ip_cidr: ($old.ip_cidr + $new.ip_cidr | unique | sort)}]}' "srs/json/same/games-same.json" "$same_temp_file" > "srs/json/same/games-same.json.tmp" && mv "srs/json/same/games-same.json.tmp" "srs/json/same/games-same.json"
          echo "  增量更新 games-same.json"
        else
          mv "$same_temp_file" "srs/json/same/games-same.json"
        fi
        optimize_json_file "srs/json/same/games-same.json"
      fi
      ;;
    "network-cn"|"network-noncn")
      compare_cn_pairs "srs/json/network-cn.json" "srs/json/network-noncn.json" "$same_temp_file"
      if [ -f "$same_temp_file" ]; then
        if [ -f "srs/json/same/network-same.json" ]; then
          jq -s '.[0].rules[0] as $old | .[1].rules[0] as $new | {version: 1, rules: [{domain: ($old.domain + $new.domain | unique | sort), domain_suffix: ($old.domain_suffix + $new.domain_suffix | unique | sort), domain_keyword: ($old.domain_keyword + $new.domain_keyword | unique | sort), domain_regex: ($old.domain_regex + $new.domain_regex | unique | sort), ip_cidr: ($old.ip_cidr + $new.ip_cidr | unique | sort)}]}' "srs/json/same/network-same.json" "$same_temp_file" > "srs/json/same/network-same.json.tmp" && mv "srs/json/same/network-same.json.tmp" "srs/json/same/network-same.json"
          echo "  增量更新 network-same.json"
        else
          mv "$same_temp_file" "srs/json/same/network-same.json"
        fi
        optimize_json_file "srs/json/same/network-same.json"
      fi
      ;;
  esac
  rm -f "$same_temp_file" # 清理临时文件
}

# ========== 7. 清理和统计 (工具函数) ==========
cleanup_old_backups() {
  echo "清理旧备份..."
  # 保留最近3个备份
  find srs/json -name "*.bak.*" -type f | sort -r | tail -n +4 | xargs -r rm -f 2>/dev/null || true
  # 清理所有临时文件
  rm -f temp/*.json temp/*.jq temp/*.tmp temp/*.temp temp/*.fixed temp/ip_merge_log.txt
}

print_size_stats() {
  echo "=== JSON 文件大小统计 ==="
  for json_file in srs/json/*.json; do
    if [ -f "$json_file" ] && [[ "$json_file" != *.bak.* ]]; then
      local size=$(stat -c %s "$json_file" 2>/dev/null || echo 0)
      printf "  %-40s: %10d 字节\n" "$(basename "$json_file")" "$size"
    fi
  done
  for json_file in srs/json/same/*.json; do
    if [ -f "$json_file" ] && [[ "$json_file" != *.bak.* ]]; then
      local size=$(stat -c %s "$json_file" 2>/dev/null || echo 0)
      printf "  %-40s: %10d 字节\n" "same/$(basename "$json_file")" "$size"
    fi
  done

  echo "=== SRS 文件大小统计 ==="
  for srs_file in srs/*.srs; do
    if [ -f "$srs_file" ]; then
      local size=$(stat -c %s "$srs_file" 2>/dev/null || echo 0)
      printf "  %-40s: %10d 字节\n" "$(basename "$srs_file")" "$size"
    fi
  done
}

# ==============================================
# ========== 脚本执行入口 ==========
# ==============================================

echo "检查依赖..."
check_dependencies

# 预处理配置（"基础URL" "排除URL" "输出文件" "类型"）
preprocess_configs=(
# game
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-cn@!cn.json"
  "srs/json/geosite-category-games-cn@cn2.json"
# "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games-!cn@cn.json"
  "srs/json/geosite-category-games-!cn@!cn.json"
# "!cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-game-platforms-download.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-game-platforms-download@cn.json"
  "srs/json/game-platforms-download@!cn.json"
# "!cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-epicgames.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-epicgames@cn.json"
  "srs/json/geosite-epicgames@!cn.json"
# "!cn"
# ai
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ai-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ai-cn@!cn.json"
  "srs/json/geosite-category-ai-cn@cn.json"
# "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-doubao.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-doubao@!cn.json"
  "srs/json/doubao@cn.json"
# "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-jetbrains.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-jetbrains@cn.json"
  "srs/json/jetbrains@!cn.json"
# "!cn"
# network
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-cn@!cn.json"
  "srs/json/geosite-category-social-media-cn@cn.json"
# "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-bank-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-bank-cn@!cn.json"
  "srs/json/geosite-category-bank-cn@cn.json"
# "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-dev-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-dev-cn@!cn.json"
  "srs/json/geosite-category-dev-cn@cn2.json"
# "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-entertainment-cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-entertainment-cn@!cn.json"
  "srs/json/geosite-category-entertainment-cn@cn2.json"
# "cn"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-!cn.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-social-media-!cn@cn.json"
  "srs/json/geosite-category-social-media-!cn@!cn.json"
# "!cn"
)


# --- 步骤 A: 预处理、优化和对比 ---
echo "--- 步骤 A: 预处理、优化和对比 ---"

# 1. 执行预处理 (规则减法)
if [ ${#preprocess_configs[@]} -gt 0 ]; then
  echo "开始预处理..."
  for ((i=0; i<${#preprocess_configs[@]}; i+=4)); do
    preprocess_ruleset "${preprocess_configs[i]}" "${preprocess_configs[i+1]}" \
                       "${preprocess_configs[i+2]}" "${preprocess_configs[i+3]}" || \
      echo "  跳过失败的预处理"
  done
  echo "预处理完成!"
fi

# 2. 创建默认 private 文件 (如果不存在)
DEFAULT_PRIVATE="srs/json/geoip-private.json"
if [ ! -f "$DEFAULT_PRIVATE" ]; then
  echo "创建默认 $DEFAULT_PRIVATE..."
  cat > "$DEFAULT_PRIVATE" << 'EOF'
{
  "version": 1,
  "rules": [{
    "ip_cidr": [
      "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
      "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
      "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
      "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
      "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "::ffff:0:0/96",
      "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
      "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"
    ]
  }]
}
EOF
fi

# 3. 优化所有 srs/json/ 中的文件 (为对比做准备)
echo "优化所有现有JSON文件..."
for json_file in srs/json/*.json; do
  if [ -f "$json_file" ] && [[ "$json_file" != *.bak.* ]]; then
    optimize_json_file "$json_file"
  fi
done

# 4. 对比 CN/!CN 文件
echo "对比 CN/!CN 文件..."
compare_cn_pairs "srs/json/ai-cn.json" "srs/json/ai-noncn.json" "srs/json/same/ai-same.json"
compare_cn_pairs "srs/json/games-cn.json" "srs/json/games-noncn.json" "srs/json/same/games-same.json"
compare_cn_pairs "srs/json/network-cn.json" "srs/json/network-noncn.json" "srs/json/same/network-same.json"

# 5. 优化新生成的 "same" 文件
echo "优化 'same' 文件..."
for same_file in srs/json/same/*.json; do
  [ -f "$same_file" ] && optimize_json_file "$same_file"
done

echo "--- 步骤 A 完成 ---"


# --- 步骤 B: 定义URL并执行主合并 ---
echo "--- 步骤 B: 定义URL并执行主合并 ---"

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
  "srs/json/geoip-private.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-private.json"
  "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-private.json"
)

# 检查 URL 数组是否已定义
if [ -z ${ads_urls+x} ]; then
  echo "错误: URL 数组 (ads_urls, ...) 未在脚本中定义。"
  echo "请在 '步骤 B' 注释块中填充它们。"
  exit 1
fi

# 执行主合并
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

echo "--- 步骤 B 完成 ---"

# --- 步骤 C: 清理和统计 ---
echo "--- 步骤 C: 清理和统计 ---"
cleanup_old_backups
print_size_stats

echo "=== 所有任务完成 ==="
echo "JSON文件位于: srs/json/"
echo "SRS文件位于: srs/"
echo "共同规则文件位于: srs/json/same/"

# --- Git 提交 (可选) ---
# echo "正在提交更改..."
# git config --global user.name "GitHub Actions"
# git config --global user.email "actions@github.com"
# git add srs/ srs/json/ srs/json/same/
# git commit -m "每日规则更新: $(date +%Y-%m-%d)" || echo "没有更改可提交"
# git push
