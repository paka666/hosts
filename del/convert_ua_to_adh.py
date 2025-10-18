import re
import re2  # 用于校验 RE2 兼容性 (pip install re2)

def convert_and_validate(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None  # 跳过空行和注释

    # 替换不支持的锚点
    line = re.sub(r'\\A', '^', line)
    line = re.sub(r'\\Z', '$', line)
    line = re.sub(r'\\z', '$', line)  # 额外处理 \z

    # 删除不支持的 lookaround 和其他 PCRE 特性
    line = re.sub(r'\(\?<?!?[=][^)]*\)', '', line)  # lookaround 如 (?=...)、(?!...)、(?<=...) 等
    line = re.sub(r'\(\?i\)', '', line)  # 删除 (?i) case-insensitive（RE2 不支持内嵌）
    line = re.sub(r'\\R|\\r', '', line)  # 删除换行相关

    # 如果已经是 /.../ 格式，保留；否则加上
    if not (line.startswith('/') and line.endswith('/')):
        line = f'/{line}/'

    # 去掉外层的 / 以校验内部 pattern
    pattern = line[1:-1]

    # 校验是否 RE2 兼容
    try:
        re2.compile(pattern)
        return line
    except re2.error:
        print(f"⚠️ 无效规则 (RE2 不支持): {line} - 已跳过")
        return None

def main(input_file="ua.txt", output_file="ua_adh.txt"):
    valid_count = 0
    skipped_count = 0

    with open(input_file, "r", encoding="utf-8") as f_in, open(output_file, "w", encoding="utf-8") as f_out:
        for line in f_in:
            new_line = convert_and_validate(line)
            if new_line:
                f_out.write(new_line + "\n")
                valid_count += 1
            else:
                skipped_count += 1

    print(f"✅ 转换完成！输出文件: {output_file}")
    print(f"   - 有效规则: {valid_count}")
    print(f"   - 跳过规则: {skipped_count} (空行/注释/无效正则)")

if __name__ == "__main__":
    main()
