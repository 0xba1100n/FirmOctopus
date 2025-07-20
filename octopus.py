#!/usr/bin/env python3
"""
IoT 固件侦察工具（ANSI 颜色，深色终端）

该脚本扫描已提取的 IoT 固件文件系统，查找：
 1. Web 相关文件 (.php, .py, .asp, .htm, .html)
 2. 常见敏感文件 (passwd, shadow, httpd.conf, .env)
 3. init.d 目录下的启动脚本
 4. 文件中“admin”和“root”关键字出现情况，排除静态文件 (.js, .shtml, .html, .xml)
 5. 所有包含“httpd”字样的服务文件（minihttpd、uhttpd 等），以及引用 cgiMain、httpd_init、websFormDefine 的文件

特性：
 - 限制输出行的最大宽度以提高可读性
 - 使用 ANSI 转义码输出彩色，无需第三方库
 - 为深色终端优化的明亮配色
 - 在 "用户关键词" 小节展示关键词列表

用法：
    python3 iot_recon_ansi.py /path/to/extracted/firmware
"""

import re
import sys
import argparse
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
DEFAULT_KEYWORDS =  [
    'admin', 'root:','passwd',         
    'sshd', 'telnetd','ftpd','udhcpd','miniupnpd',
    'smbd','smbd',
]

# 输出每行的最大字符数
MAX_WIDTH = 100

# 各部分的中文描述
SECTION_DESCRIPTIONS = {
    'Web Files': '网页文件',
    'Common Sensitive Files': '常见敏感文件',
    'Init.d Scripts': '启动脚本',
    'HTTPD Services': 'HTTPD 服务文件',
    'User Keywords': '用户关键词'
}

# 各部分对应的颜色
SECTION_COLORS = {
    'Web Files': 'cyan',
    'Common Sensitive Files': 'magenta',
    'Init.d Scripts': 'yellow',
    'HTTPD Services': 'white',
    'User Keywords': 'green'
}

# 获取当前脚本名称，用于排除自身
SCRIPT_NAME = Path(__file__).name


def truncate(text, width=MAX_WIDTH):
    """截断文本到最大宽度，超出部分用省略号替代。"""
    return text if len(text) <= width else text[:width-3] + '...'


def is_binary_file(filepath, blocksize=1024):
    """通过检测前 blocksize 字节中是否包含\0 来判断是否二进制文件。"""
    try:
        with open(filepath, 'rb') as f:
            return b'\x00' in f.read(blocksize)
    except Exception:
        return False


def find_files(root, patterns):
    """遍历根目录，查找匹配扩展名或文件名的文件并返回结果字典，排除脚本自身。"""
    results = {label: [] for label in patterns}
    for path in Path(root).rglob('*'):
        if not path.is_file() or path.name == SCRIPT_NAME:
            continue
        for label, exts in patterns.items():
            for ext in exts:
                # 支持扩展名与文件名匹配
                if ext.startswith('.') and path.suffix.lower() == ext:
                    results[label].append(str(path))
                elif not ext.startswith('.') and path.name.lower() == ext:
                    results[label].append(str(path))
    return results


def find_init_scripts(root):
    """在所有 init.d 目录下查找脚本文件，排除扫描脚本本身。"""
    scripts = []
    for dirpath in Path(root).rglob('init.d'):
        if dirpath.is_dir():
            for script in dirpath.iterdir():
                if script.is_file() and script.name != SCRIPT_NAME:
                    scripts.append(str(script))
    return scripts


def find_httpd_services(root):
    """查找所有包含“httpd”字样且具有执行权限的文件，以及包含指定 Web 服务函数引用的文件，去重后返回。"""
    services = set()
    # 按文件名查找 httpd 二进制
    for path in Path(root).rglob('*'):
        if (not path.is_file() or path.name == SCRIPT_NAME):
            continue
        name_lower = path.name.lower()
        try:
            if 'httpd' in name_lower and (path.stat().st_mode & 0o111) and is_binary_file(path):
                services.add(str(path))
        except Exception:
            continue
    # 扫描文件内容，查找特定函数引用
    keywords = ['cgiMain', 'httpd_init', 'websFormDefine']
    for path in Path(root).rglob('*'):
        if not path.is_file() or path.name == SCRIPT_NAME:
            continue
        try:
            with path.open(errors='ignore') as f:
                content = f.read()
            for k in keywords:
                if k in content:
                    services.add(str(path))
                    break
        except Exception:
            continue
    # 返回去重列表
    return list(services)


def detect_user_keywords(root, keywords=None):
    """检测指定关键词在非静态文件中的出现，并高亮匹配片段，排除硬编码列表中的可执行文件与静态资源。"""
    if keywords is None:
        keywords = DEFAULT_KEYWORDS

    # 负向环视：排除紧挨 <, >, - 的匹配
    pattern = re.compile(
        rf"(?i)(?<![<>-])\b({'|'.join(re.escape(k) for k in keywords)})\b(?![<>-])"
    )

    # 排除的文件扩展名
    excluded_exts = {'.js', '.shtml', '.html', '.xml', '.asp', '.htm', '.aspx'}

    # 硬编码要跳过的可执行文件名（不含路径）
    skip_names = {
        'busybox', 'dnsmasq', 'igmpproxy', 'inadyn',
        'ip', 'l2tpv3tun', 'miniupnpd', 'openssl',
        'pppd', 'tc'
    }

    hits = []
    for path in Path(root).rglob('*'):
        name = path.name.lower()
        ext  = path.suffix.lower()

        # 跳过：不是普通文件、脚本自身、在硬编码列表里，或属于静态扩展
        if (not path.is_file()
            or name == SCRIPT_NAME.lower()
            or name in skip_names
            or ext in excluded_exts):
            continue

        try:
            with path.open(errors='ignore') as f:
                for num, line in enumerate(f, 1):
                    if pattern.search(line):
                        snippet = truncate(line.strip())
                        # 高亮关键词
                        snippet = pattern.sub(
                            lambda m: COLORS['red'] + m.group(0) + RESET,
                            snippet
                        )
                        hits.append((str(path), num, snippet))
        except Exception:
            continue

    return hits


def print_header(title):
    """打印彩色标题并在下方添加对应长度的下划线。"""
    desc = SECTION_DESCRIPTIONS.get(title, '')
    display = f"{desc} ({title})" if desc else title
    color = COLORS.get(SECTION_COLORS.get(title, ''), '')
    print(f"{BOLD}{color}{display}{RESET}")
    print(f"{color}{'-' * len(display)}{RESET}")


def print_section(title, lines):
    """打印分节内容，行前加两格缩进并使用对应颜色。"""
    print_header(title)
    for line in lines:
        print(f"  {COLORS.get(SECTION_COLORS.get(title, ''), '')}{truncate(line)}{RESET}")
    print()


def print_httpd_services(services):
    """打印 HTTPD 服务文件，仅保留二进制文件。"""
    print_header('HTTPD Services')
    for path in services or ['None']:
        print(f"  {COLORS.get(SECTION_COLORS['HTTPD Services'], '')}{truncate(path)}{RESET}")
    print()


def print_user_hits(hits):
    """打印“用户关键词”小节，包括关键词列表和匹配结果。"""
    print_header('User Keywords')
    print(f"  {COLORS['green']}关键词列表: {', '.join(DEFAULT_KEYWORDS)}{RESET}\n")
    for path, num, snippet in hits or [('None', '', '')]:
        file_col = COLORS['yellow'] + truncate(path) + RESET
        line_col = COLORS['cyan'] + str(num) + RESET
        print(f"  {file_col}:{line_col}: {snippet}")
    print()


def main():
    parser = argparse.ArgumentParser(description="使用 ANSI 颜色输出的 IoT 固件侦察工具")
    parser.add_argument('path', help='固件文件系统根目录路径')
    args = parser.parse_args()
    root = args.path

    patterns = {
        'Web Files': ['.php', '.asp', '.htm', '.html', '.py', '.jsp','.cgi'],
        'Common Sensitive Files': ['passwd', 'shadow', 'httpd.conf', '.env'],
    }
    results = find_files(root, patterns)
    init_scripts = find_init_scripts(root)
    httpd_services = find_httpd_services(root)
    user_hits = detect_user_keywords(root)

    for section, items in results.items():
        print_section(section, items or ['None'])
    print_section('Init.d Scripts', init_scripts or ['None'])
    print_httpd_services(httpd_services)
    print_user_hits(user_hits)

if __name__ == '__main__':
    main()
