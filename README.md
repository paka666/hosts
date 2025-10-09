# IP Blocklists for AdGuardHome

自动生成的IP黑名单，适用于AdGuardHome。

## 统计信息

- **总网络数**: 1558696
- **IPv4网络**: 1557358
- **IPv6网络**: 1338

## 文件说明

- `adguard-ip-blocklist.txt` - AdGuardHome专用格式，包含所有IPv4和IPv6网络
- `ipv4-list.txt` - 纯IPv4网络列表  
- `ipv6-list.txt` - 纯IPv6网络列表

## 数据来源

1. [firehol/blocklist-ipsets](https://github.com/firehol/blocklist-ipsets) - ZIP压缩包，包含多个.ipset/.netset文件
2. [bitwire-it/ipblocklist](https://github.com/bitwire-it/ipblocklist) - inbound.txt
3. [bitwire-it/ipblocklist](https://github.com/bitwire-it/ipblocklist) - outbound.txt

## 处理流程

1. 下载所有源数据
2. 解压并清理ZIP文件（移除.md/.gitignore/.sh文件）
3. 从所有.ipset/.netset/.txt文件中提取IP和CIDR
4. 合并去重所有IP/CIDR
5. 使用Radix树进行网络优化（去除被包含的子网）
6. 分离IPv4和IPv6地址
7. 排序并生成最终文件

## 使用说明

在AdGuardHome的DNS黑名单中添加URL

## 更新频率

每天自动更新。

---

*最后更新: 2025-10-09 11:58:11*
