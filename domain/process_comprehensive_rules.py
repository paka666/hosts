#!/usr/bin/env python3
import os
import re
import asyncio
import aiohttp
import ipaddress
import tempfile
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# 配置数据源 - 添加更多规则源
RULE_SOURCES = [
    "https://adaway.org/hosts.txt",
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_13.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_15.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_19.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_20.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_25.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_26.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_35.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_36.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_37.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_40.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_43.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_45.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_46.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_57.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_62.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_64.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_66.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_68.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_69.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_70.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_71.txt",
    "https://adrules.top/dns.txt",
    "https://anti-ad.net/easylist.txt",
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://easylist.to/easylist/fanboy-social.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina+easylist.txt",
    "https://github.com/cjx82630/cjxlist/raw/master/cjx-annoyance.txt",
    "https://github.com/cjx82630/cjxlist/raw/master/cjxlist.txt",
    "https://github.com/cjx82630/cjxlist/raw/master/cjx-ublock.txt",
    "https://github.com/Goooler/1024_hosts/raw/master/hosts",
    "https://github.com/o0HalfLife0o/list/raw/master/ad.txt",
    "https://github.com/StevenBlack/hosts/raw/master/hosts",
    "https://github.com/xinggsf/Adblock-Plus-Rule/raw/master/minority-mv.txt",
    "https://github.com/xinggsf/Adblock-Plus-Rule/raw/master/mv.txt",
    "https://github.com/xinggsf/Adblock-Plus-Rule/raw/master/rule.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/tekintian/hosts_ads_block/master/mobile/hosts",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-hosts.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Replenish.txt",
    "https://raw.githubusercontent.com/vokins/yhosts/master/hosts",
    "https://raw.githubusercontent.com/yous/YousList/master/hosts.txt",
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
    "https://someonewhocares.org/hosts/hosts",
    "https://sysctl.org/cameleon/hosts",
    "https://winhelp2002.mvps.org/hosts.txt",
    "https://www.hostsfile.org/Downloads/hosts.txt"
]

class ComprehensiveRuleProcessor:
    def __init__(self):
        # 存储各类规则
        self.n1_all_rules = set()  # 所有预处理后的规则
        self.n2_pure_ips = set()   # 纯IP
        self.n3_pure_domains = set()  # 纯域名
        self.n5_hosts_rules = set()   # hosts规则
        self.a_rules = set()       # 含IP的非纯IP规则
        self.b_rules = set()       # 含域名的非纯域名规则
        
    async def download_with_retry(self, session, url, max_retries=3):
        """带重试的下载"""
        for attempt in range(max_retries):
            try:
                async with session.get(url, timeout=60) as response:
                    if response.status == 200:
                        content = await response.text()
                        return url, content, True
                    else:
                        print(f"下载失败 {url}: HTTP {response.status}, 尝试 {attempt + 1}/{max_retries}")
            except Exception as e:
                print(f"下载失败 {url}: {e}, 尝试 {attempt + 1}/{max_retries}")
            
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # 指数退避
        
        return url, None, False
    
    async def download_all_sources(self, sources):
        """多线程下载所有源"""
        print(f"开始多线程下载 {len(sources)} 个源...")
        
        connector = aiohttp.TCPConnector(limit=10)  # 限制并发连接数
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.download_with_retry(session, url) for url in sources]
            results = await asyncio.gather(*tasks)
            
        success_count = sum(1 for _, _, success in results if success)
        print(f"下载完成: {success_count}/{len(sources)} 个源成功")
        
        return results
    
    def remove_comments_and_empty_lines(self, content):
        """移除注释行和空行"""
        lines = []
        for line in content.splitlines():
            clean_line = line.strip()
            
            # 跳过空行
            if not clean_line:
                continue

            # 只跳过以!开头的行（修改这里）
            if re.match(r'^\s*!', clean_line):
                continue

            lines.append(clean_line)
            
        return lines
    
    def is_pure_ip(self, text):
        """检查是否为纯IP/CIDR"""
        try:
            # 尝试解析为IP网络
            ipaddress.ip_network(text, strict=False)
            return True
        except:
            return False
    
    def is_pure_domain(self, text):
        """检查是否为纯域名"""
        # 简单的域名格式检查，不包含特殊字符和空格
        domain_pattern = r'^[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$'
        if not re.match(domain_pattern, text):
            return False
        
        # 确保不是IP地址
        if self.is_pure_ip(text):
            return False
            
        return True
    
    def is_hosts_rule(self, text):
        """检查是否为hosts规则并处理"""
        # hosts格式: IP domain [domain2 ...]
        hosts_match = re.match(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([^\s#!]+)(?:\s+[^\s#!]+)*\s*$', text)
        if hosts_match:
            ip, first_domain = hosts_match.groups()
            # 将127.0.0.1改为0.0.0.0
            if ip == '127.0.0.1':
                new_ip = '0.0.0.0'
                # 重建规则行
                domains = text.split()[1:]
                new_line = f"{new_ip} {' '.join(domains)}"
                return True, new_line
            else:
                return True, text
        return False, text
    
    def contains_ip(self, text):
        """检查是否包含IP"""
        ip_patterns = [
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b',
            r'\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}(?:/\d{1,3})?\b'
        ]
        return any(re.search(pattern, text) for pattern in ip_patterns)
    
    def contains_domain(self, text):
        """检查是否包含域名"""
        domain_pattern = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return re.search(domain_pattern, text) is not None
    
    def classify_rule(self, rule):
        """分类规则"""
        # 检查纯IP
        if self.is_pure_ip(rule):
            self.n2_pure_ips.add(rule)
            return
        
        # 检查纯域名
        if self.is_pure_domain(rule):
            self.n3_pure_domains.add(rule)
            return
        
        # 检查hosts规则
        is_hosts, processed_rule = self.is_hosts_rule(rule)
        if is_hosts:
            self.n5_hosts_rules.add(processed_rule)
            return
        
        # 剩下的规则分类为a或b
        has_ip = self.contains_ip(rule)
        has_domain = self.contains_domain(rule)
        
        if has_ip:
            self.a_rules.add(rule)
        elif has_domain:
            self.b_rules.add(rule)
        # 如果既没有IP也没有域名，则忽略
    
    def process_all_rules(self, download_results):
        """处理所有规则"""
        print("预处理规则...")
        
        for url, content, success in download_results:
            if not success or not content:
                continue
                
            # 移除注释和空行，得到n1
            clean_lines = self.remove_comments_and_empty_lines(content)
            self.n1_all_rules.update(clean_lines)
        
        print(f"预处理完成: {len(self.n1_all_rules)} 条规则")
        
        # 分类处理每条规则
        print("分类处理规则...")
        for rule in self.n1_all_rules:
            self.classify_rule(rule)
        
        # 验证 n4 = n1 - n2 - n3
        n4_expected = self.n1_all_rules - self.n2_pure_ips - self.n3_pure_domains
        
        # 验证 n6 = n4 - n5
        n6_expected = n4_expected - self.n5_hosts_rules
        
        # 验证 a + b = n6
        a_b_union = self.a_rules | self.b_rules
        if a_b_union != n6_expected:
            print(f"警告: 分类不一致, a+b ({len(a_b_union)}) != n6 ({len(n6_expected)})")
        
        return {
            'n1': len(self.n1_all_rules),
            'n2': len(self.n2_pure_ips),
            'n3': len(self.n3_pure_domains),
            'n4': len(n4_expected),
            'n5': len(self.n5_hosts_rules),
            'n6': len(n6_expected),
            'a': len(self.a_rules),
            'b': len(self.b_rules)
        }
    
    def write_output_files(self):
        """写入输出文件"""
        print("写入输出文件...")
        
        # 创建目录
        Path("rules/other").mkdir(parents=True, exist_ok=True)
        Path("rules/domain").mkdir(parents=True, exist_ok=True)
        Path("rules/hosts").mkdir(parents=True, exist_ok=True)
        
        # 写入纯IP (n2)
        if self.n2_pure_ips:
            with open("rules/other/pure_ip.txt", "w", encoding="utf-8") as f:
                f.write("# Pure IP/CIDR Rules\n")
                f.write(f"# Total: {len(self.n2_pure_ips)}\n\n")
                for rule in sorted(self.n2_pure_ips):
                    f.write(rule + "\n")
            print(f"✓ 写入 rules/other/pure_ip.txt ({len(self.n2_pure_ips)} 条)")
        
        # 写入纯域名 (n3)
        if self.n3_pure_domains:
            with open("rules/other/pure_domain.txt", "w", encoding="utf-8") as f:
                f.write("# Pure Domain Rules\n")
                f.write(f"# Total: {len(self.n3_pure_domains)}\n\n")
                for rule in sorted(self.n3_pure_domains):
                    f.write(rule + "\n")
            print(f"✓ 写入 rules/other/pure_domain.txt ({len(self.n3_pure_domains)} 条)")
        
        # 写入hosts规则 (n5)
        if self.n5_hosts_rules:
            with open("rules/hosts/hosts.txt", "w", encoding="utf-8") as f:
                f.write("# Hosts Rules (127.0.0.1 → 0.0.0.0)\n")
                f.write(f"# Total: {len(self.n5_hosts_rules)}\n\n")
                for rule in sorted(self.n5_hosts_rules):
                    f.write(rule + "\n")
            print(f"✓ 写入 rules/hosts/hosts.txt ({len(self.n5_hosts_rules)} 条)")
        
        # 写入A类规则
        if self.a_rules:
            with open("rules/domain/a.txt", "w", encoding="utf-8") as f:
                f.write("# A Rules (Contains IP but not pure IP)\n")
                f.write(f"# Total: {len(self.a_rules)}\n\n")
                for rule in sorted(self.a_rules):
                    f.write(rule + "\n")
            print(f"✓ 写入 rules/domain/a.txt ({len(self.a_rules)} 条)")
        
        # 写入B类规则
        if self.b_rules:
            with open("rules/domain/b.txt", "w", encoding="utf-8") as f:
                f.write("# B Rules (Contains domain but not pure domain)\n")
                f.write(f"# Total: {len(self.b_rules)}\n\n")
                for rule in sorted(self.b_rules):
                    f.write(rule + "\n")
            print(f"✓ 写入 rules/domain/b.txt ({len(self.b_rules)} 条)")
    
    def update_readme(self, stats):
        """更新README文件"""
        from datetime import datetime
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        readme_content = f"""# Comprehensive Rules

自动分类处理的规则集合。

## 统计信息

- **总规则数 (n1)**: {stats['n1']}
- **纯IP规则 (n2)**: {stats['n2']}
- **纯域名规则 (n3)**: {stats['n3']}
- **剩余规则 (n4)**: {stats['n4']}
- **Hosts规则 (n5)**: {stats['n5']}
- **混合规则 (n6)**: {stats['n6']}
- **A类规则 (含IP)**: {stats['a']}
- **B类规则 (含域名)**: {stats['b']}

## 文件说明

### rules/other/
- `pure_ip.txt` - 纯IP/CIDR规则
- `pure_domain.txt` - 纯域名规则

### rules/domain/
- `a.txt` - 含IP的非纯IP规则
- `b.txt` - 含域名的非纯域名规则

### rules/hosts/
- `hosts.txt` - Hosts格式规则 (127.0.0.1 → 0.0.0.0)

## 处理流程

1. **下载**: 多线程下载所有规则源
2. **预处理**: 移除注释行 (! # // /* 开头) 和空行 → n1
3. **分类**:
   - 提取纯IP → n2
   - 提取纯域名 → n3
   - n4 = n1 - n2 - n3
   - 提取hosts规则 (127.0.0.1 → 0.0.0.0) → n5
   - n6 = n4 - n5
   - 提取A类规则 (含IP的非纯IP) → a
   - 提取B类规则 (含域名的非纯域名) → b

## 更新频率

每天自动更新。

---

*最后更新: {current_time}*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        print("✓ 更新 README.md")

async def main():
    start_time = time.time()
    
    processor = ComprehensiveRuleProcessor()
    
    # 下载所有源
    download_results = await processor.download_all_sources(RULE_SOURCES)
    
    # 处理所有规则
    stats = processor.process_all_rules(download_results)
    
    # 写入输出文件
    processor.write_output_files()
    
    # 更新README
    processor.update_readme(stats)
    
    end_time = time.time()
    
    print(f"\n{'='*60}")
    print("处理完成!")
    print(f"{'='*60}")
    print(f"执行时间: {end_time - start_time:.2f} 秒")
    print(f"总规则: {stats['n1']}")
    print(f"纯IP: {stats['n2']}")
    print(f"纯域名: {stats['n3']}")
    print(f"Hosts规则: {stats['n5']}")
    print(f"A类规则: {stats['a']}")
    print(f"B类规则: {stats['b']}")
    print(f"{'='*60}")

if __name__ == "__main__":
    asyncio.run(main())
