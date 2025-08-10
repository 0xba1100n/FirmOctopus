#!/usr/bin/env python3 
"""
IoT Firmware Recon Tool (ANSI Colors, Dark Terminal)

This script scans an extracted IoT firmware file system to find:
 1. Web-related files (.php, .py, .asp, .htm, .html)
 2. Common sensitive files (passwd, shadow, httpd.conf, .env, hidden files .passwd, .shadow)
 3. Startup scripts in the init.d directory
 4. Occurrence of the keywords “admin” and “root” in files, excluding static files (.js, .shtml, .html, .xml)
 5. All service files containing "httpd" (minihttpd, uhttpd, etc.), and files referencing cgiMain, httpd_init, websFormDefine
 6. Custom reconnaissance: Based on user-defined dictionary (keys as labels, values as (pattern, mode type)), determine firmware structure type by pattern (0: grep content, 1: filename match), and output a summary at the end
 7. If Goahead is detected, execute strings usr/lib/libWebs.so to extract the Goahead version and display it
    If nginx is detected, execute grep -ril "location /" <root> and output a list of files with location /
    If lighttpd is detected, execute grep -rIl "auth\.require" <root> and output a list of lighttpd permission files

Features:
 - Restricts the maximum line width for better readability
 - Uses ANSI escape codes to output colors, no need for third-party libraries
 - Optimized bright color scheme for dark terminals
 - Displays keyword list in the "User Keywords" section
 - Outputs a summary of custom reconnaissance, nginx route files, lighttpd permission files, and Goahead version at the end, without listing detailed files
 - Adds progress indication to improve the user waiting experience

Usage:
    python3 iot_recon_ansi_modified.py /path/to/extracted/firmware
"""

import os
import re
import sys
import argparse
import subprocess
from pathlib import Path

# ANSI escape codes (bright colors)
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

# Default keyword list
DEFAULT_CONFIG_KEYWORDS = ['admin', 'root:', 'passwd']

# Custom reconnaissance dictionary: key is label (description), value is (pattern string, detection mode)
# Detection mode: 0 = grep content, 1 = filename match
CUSTOM_PATTERNS = {
    'Lua': ('.lua', 1),
    'Asp': ('.asp', 1),
    'Static HTML': ('.htm', 1),
    'PHP': ('.php', 1),
    'CGI': ('.cgi', 1),
    'nginx': ('nginx', 1),
    'Goahead': ('goahead', 0),
    'lighttpd': ('lighttpd', 0)
}

# Excluded file extensions (won't be included in any output)
EXCLUDED_SUFFIXES = {'.id0', '.id1', '.nam'}

# Maximum line width for output
MAX_WIDTH = 100

# Section descriptions in English
SECTION_DESCRIPTIONS = {
    'Web Files': 'Web Files',
    'Common Sensitive Files': 'Common Sensitive Files',
    'Init.d Scripts': 'Startup Scripts',
    'HTTPD Services': 'HTTPD Service Files',
    'Config Recon': 'Configuration Files'
}

# Colors for each section
SECTION_COLORS = {
    'Web Files': 'cyan',
    'Common Sensitive Files': 'magenta',
    'Init.d Scripts': 'yellow',
    'HTTPD Services': 'white',
    'Config Recon': 'green'
}

SCRIPT_NAME = Path(__file__).name.lower()


def truncate(text, width=MAX_WIDTH):
    return text if len(text) <= width else text[:width - 3] + '...'


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
    print(f"  {COLORS['green']}Keyword List: {', '.join(DEFAULT_CONFIG_KEYWORDS)}{RESET}\n")
    for path, num, snippet in hits or [('None', '', '')]:
        fp = COLORS['yellow'] + truncate(path) + RESET
        ln = COLORS['cyan'] + str(num) + RESET
        print(f"  {fp}:{ln}: {snippet}")
    print()


def main():
    parser = argparse.ArgumentParser(description="IoT Firmware Recon Tool with ANSI colors")
    parser.add_argument('path', help='Root directory path of the extracted firmware file system')
    args = parser.parse_args()
    root = args.path

    print(f"{COLORS['cyan']}[+] Scanning Web files and sensitive files...{RESET}")
    patterns = {
        'Web Files': ['.php', '.asp', '.htm', '.html', '.py', '.jsp', '.cgi', '.lua'],
        'Common Sensitive Files': ['passwd', 'shadow', '.passwd', '.shadow', 'httpd.conf', '.env'],
    }
    results = find_files(root, patterns)

    print(f"{COLORS['yellow']}[+] Scanning init.d startup scripts...{RESET}")
    init_scripts = find_init_scripts(root)

    print(f"{COLORS['white']}[+] Scanning HTTPD service files...{RESET}")
    httpd_services = find_httpd_services(root)

    print(f"{COLORS['green']}[+] Detecting configuration keywords...{RESET}")
    user_hits = detect_user_keywords(root)

    print(f"{COLORS['magenta']}[+] Performing custom pattern reconnaissance...{RESET}")
    custom_hits = detect_custom_patterns(root, CUSTOM_PATTERNS)

    goahead_version = None
    if 'Goahead' in custom_hits:
        goahead_version = extract_goahead_version(root)

    for section, items in results.items():
        print_section(section, items or ['None'])
    print_section('Init.d Scripts', init_scripts or ['None'])
    print_httpd_services(httpd_services)
    print_user_hits(user_hits)

    if custom_hits:
        summary = '+'.join(custom_hits)
        print(f"{COLORS['green']}This firmware is of {summary} structure{RESET}")
        if 'nginx' in custom_hits:
            try:
                res = subprocess.run(['grep', '-ril', 'location /', str(root)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                files = [f for f in res.stdout.decode(errors='ignore').splitlines() if f]
            except Exception:
                files = []
            if files:
                print(f"{COLORS['green']}[+] nginx route files found: {', '.join(files)}{RESET}\n")
        if 'lighttpd' in custom_hits:
            try:
                res = subprocess.run(['grep', '-rIl', 'auth\.require', str(root)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                files = [f for f in res.stdout.decode(errors='ignore').splitlines() if f]
            except Exception:
                files = []
            print_header('lighttpd Permission Files')
            for f in files or ['None']:
                print(f"  {COLORS.get(SECTION_COLORS['Config Recon'], '')}{truncate(f)}{RESET}")
            print()

    if goahead_version:
        print(f"{COLORS['green']}[+] Goahead version: {goahead_version}{RESET}")
    elif 'Goahead' in custom_hits:
        print(f"{COLORS['red']}[!] Unable to extract Goahead version{RESET}")

if __name__ == '__main__':
    main()
