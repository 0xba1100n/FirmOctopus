#!/usr/bin/env python3 
"""
IoT 固件侦察工具（ANSI 颜色，深色终端）

该脚本扫描已提取的 IoT 固件文件系统，查找：
 1. Web 相关文件 (.php, .py, .asp, .htm, .html)
 2. 常见敏感文件 (passwd, shadow, httpd.conf, .env, 隐藏文件 .passwd, .shadow)
 3. init.d 目录下的启动脚本
 4. 文件中“admin”和“root”关键字出现情况，排除静态文件 (.js, .shtml, .html, .xml)
 5. 所有包含“httpd”字样的服务文件（minihttpd、uhttpd 等），以及引用 cgiMain、httpd_init、websFormDefine 的文件
 6. 自定义侦查：基于用户定义的字典（键为标签，值为 (模式, 模式类型)），按模式（0: grep 内容，1: 文件名匹配）判断固件结构类型，并在末尾输出汇总
 7. 如果检测到 Goahead，则在所有输出结束后，执行 strings usr/lib/libWebs.so 提取 Goahead 版本号并显示

特性：
 - 限制输出行的最大宽度以提高可读性
 - 使用 ANSI 转义码输出彩色，无需第三方库
 - 为深色终端优化的明亮配色
 - 在 "用户关键词" 小节展示关键词列表
 - 在最后输出自定义侦查汇总及 Goahead 版本号，不列出详细文件
 - 增加进度提示，提升用户等待体验

用法：
    python3 iot_recon_ansi_modified.py /path/to/extracted/firmware
"""

import os
import re
import sys
import argparse
import subprocess
from pathlib import Path

# ANSI 转义码（亮色）
RESET = "\033[0m"
BOLD = "\033[1m"
COLORS = {
    'cyan': "\033[96m",
    'magenta': "\033[95m",
    'yellow': "\033[93m",
    'green': "\033[92m",
    'red': "\033[91m",
    'white': "\033[97m"
}

# 默认关键词列表
DEFAULT_CONFIG_KEYWORDS = ['admin', 'root:', 'passwd']

# 自定义侦查字典：键为标签(描述)，值为 (模式字符串, 检测模式)
# 检测模式: 0 = grep 内容, 1 = 文件名匹配
CUSTOM_PATTERNS = {
    # 页面
    'Lua': ('.lua', 1),
    'Asp': ('.asp', 1),
    '静态html': ('.htm', 1),
    'PHP': ('.php', 1),

    # 路由
    'CGI': ('.cgi', 1),
    'nginx': ('nginx', 1),

    # HTTPD服务
    'Goahead': ('goahead', 0),
}

# 排除文件后缀（不参与任何输出）
EXCLUDED_SUFFIXES = {'.id0', '.id1', '.nam'}

# 输出每行的最大字符数
MAX_WIDTH = 100

# 各部分的中文描述
SECTION_DESCRIPTIONS = {
    'Web Files': '网页文件',
    'Common Sensitive Files': '常见敏感文件',
    'Init.d Scripts': '启动脚本',
    'HTTPD Services': 'HTTPD 服务文件',
    'Config Recon': '配置文件'
}

# 各部分对应的颜色
SECTION_COLORS = {
    'Web Files': 'cyan',
    'Common Sensitive Files': 'magenta',
    'Init.d Scripts': 'yellow',
    'HTTPD Services': 'white',
    'Config Recon': 'green'
}

SCRIPT_NAME = Path(__file__).name.lower()


def truncate(text, width=MAX_WIDTH):
    return text if len(text) <= width else text[:width-3] + '...'


def is_binary_file(filepath, blocksize=1024):
    try:
        with open(filepath, 'rb') as f:
            return b'\x00' in f.read(blocksize)
    except Exception:
        return False


def find_files(root, patterns):
    results = {label: [] for label in patterns}
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            lower_name = name.lower()
            path = Path(dirpath) / name
            ext = path.suffix.lower()
            if lower_name == SCRIPT_NAME or ext in EXCLUDED_SUFFIXES:
                continue
            for label, exts in patterns.items():
                for e in exts:
                    if lower_name == e.lower() or ext == e.lower():
                        results[label].append(str(path))
                        break
    return results


def find_init_scripts(root):
    scripts = []
    for dirpath, _, filenames in os.walk(root):
        if os.path.basename(dirpath) == 'init.d':
            for name in filenames:
                lower_name = name.lower()
                path = Path(dirpath) / name
                ext = path.suffix.lower()
                if lower_name == SCRIPT_NAME or ext in EXCLUDED_SUFFIXES:
                    continue
                scripts.append(str(path))
    return scripts


def find_httpd_services(root):
    services = set()
    keywords = ['cgiMain', 'httpd_init', 'websFormDefine', 'handle_request']
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            lower_name = name.lower()
            path = Path(dirpath) / name
            ext = path.suffix.lower()
            if lower_name == SCRIPT_NAME or ext in EXCLUDED_SUFFIXES:
                continue
            try:
                if 'httpd' in lower_name and (path.stat().st_mode & 0o111) and is_binary_file(path):
                    services.add(str(path))
                else:
                    content = path.read_text(errors='ignore')
                    for k in keywords:
                        if k in content:
                            services.add(str(path))
                            break
            except Exception:
                continue
    return list(services)


def detect_user_keywords(root, keywords=None):
    if keywords is None:
        keywords = DEFAULT_CONFIG_KEYWORDS
    pattern = re.compile(rf"(?i)(?<![<>-])\b({'|'.join(re.escape(k) for k in keywords)})\b(?![<>-])")
    excluded_exts = {'.js', '.shtml', '.html', '.xml', '.asp', '.htm', '.aspx'}
    hits = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            lower_name = name.lower()
            path = Path(dirpath) / name
            ext = path.suffix.lower()
            if lower_name == SCRIPT_NAME or ext in excluded_exts or ext in EXCLUDED_SUFFIXES:
                continue
            try:
                if is_binary_file(path):
                    continue
                for num, line in enumerate(path.open(errors='ignore'), 1):
                    if pattern.search(line):
                        snippet = truncate(line.strip())
                        snippet = pattern.sub(lambda m: COLORS['red'] + m.group(0) + RESET, snippet)
                        hits.append((str(path), num, snippet))
            except Exception:
                continue
    return hits


def detect_custom_patterns(root, patterns):
    matched_labels = []
    for label, (pat, mode) in patterns.items():
        found = False
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                lower_name = name.lower()
                path = Path(dirpath) / name
                ext = path.suffix.lower()
                if lower_name == SCRIPT_NAME or ext in EXCLUDED_SUFFIXES:
                    continue
                try:
                    if mode == 1 and pat.lower() in lower_name:
                        found = True
                        break
                    elif mode == 0:
                        data = path.read_bytes()
                        if pat.encode('utf-8').lower() in data.lower():
                            found = True
                            break
                except Exception:
                    continue
            if found:
                matched_labels.append(label)
                break
    return matched_labels


def extract_goahead_version(root):
    """执行 strings usr/lib/libWebs.so 并提取 Goahead 版号"""
    so_path = Path(root) / 'usr/lib/libWebs.so'
    if not so_path.is_file():
        return None
    try:
        res = subprocess.run(['strings', str(so_path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        text = res.stdout.decode(errors='ignore')
        m = re.search(r"SERVER_ADDR\s+(\d+\.\d+\.\d+)\s+SERVER_SOFTWARE", text)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def print_header(title):
    desc = SECTION_DESCRIPTIONS.get(title, '')
    disp = f"{desc} ({title})" if desc else title
    color = COLORS.get(SECTION_COLORS.get(title, ''), '')
    print(f"{BOLD}{color}{disp}{RESET}")
    print(f"{color}{'-' * len(disp)}{RESET}")


def print_section(title, lines):
    print_header(title)
    for line in lines:
        print(f"  {COLORS.get(SECTION_COLORS.get(title, ''), '')}{truncate(line)}{RESET}")
    print()


def print_httpd_services(services):
    print_header('HTTPD Services')
    for path in services or ['None']:
        print(f"  {COLORS.get(SECTION_COLORS['HTTPD Services'], '')}{truncate(path)}{RESET}")
    print()


def print_user_hits(hits):
    print_header('Config Recon')
    print(f"  {COLORS['green']}关键词列表: {', '.join(DEFAULT_CONFIG_KEYWORDS)}{RESET}\n")
    for path, num, snippet in hits or [('None', '', '')]:
        fp = COLORS['yellow'] + truncate(path) + RESET
        ln = COLORS['cyan'] + str(num) + RESET
        print(f"  {fp}:{ln}: {snippet}")
    print()


def main():
    parser = argparse.ArgumentParser(description="使用 ANSI 颜色输出的 IoT 固件侦察工具")
    parser.add_argument('path', help='固件文件系统根目录路径')
    args = parser.parse_args()
    root = args.path

    print(f"{COLORS['cyan']}[+] 正在扫描 Web 文件和敏感文件...{RESET}")
    patterns = {
        'Web Files': ['.php', '.asp', '.htm', '.html', '.py', '.jsp', '.cgi', '.lua'],
        'Common Sensitive Files': ['passwd', 'shadow', '.passwd', '.shadow', 'httpd.conf', '.env'],
    }
    results = find_files(root, patterns)

    print(f"{COLORS['yellow']}[+] 正在扫描 init.d 启动脚本...{RESET}")
    init_scripts = find_init_scripts(root)

    print(f"{COLORS['white']}[+] 正在扫描 HTTPD 服务文件...{RESET}")
    httpd_services = find_httpd_services(root)

    print(f"{COLORS['green']}[+] 正在检测配置关键字出现...{RESET}")
    user_hits = detect_user_keywords(root)

    print(f"{COLORS['magenta']}[+] 正在进行自定义模式侦查...{RESET}")
    custom_hits = detect_custom_patterns(root, CUSTOM_PATTERNS)

    # 存储 Goahead 版号，稍后输出
    goahead_version = None
    if 'Goahead' in custom_hits:
        goahead_version = extract_goahead_version(root)

    for section, items in results.items():
        print_section(section, items or ['None'])
    print_section('Init.d Scripts', init_scripts or ['None'])
    print_httpd_services(httpd_services)
    print_user_hits(user_hits)

    # 自定义侦察汇总输出
    if custom_hits:
        summary = '+'.join(custom_hits)
        print(f"{COLORS['green']}该固件是{summary}结构的文件{RESET}\n")

    # 最后输出 Goahead 版号
    if goahead_version:
        print(f"{COLORS['green']}[+] Goahead 版本号: {goahead_version}{RESET}")
    elif 'Goahead' in custom_hits:
        print(f"{COLORS['red']}[!] 未能提取到 Goahead 版本号{RESET}")

if __name__ == '__main__':
    main()
