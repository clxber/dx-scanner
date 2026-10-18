# -*- coding: utf-8 -*-
"""
高校代理扫描器 —— 五阶段 + 分片 + 断点续跑

阶段 1 verify_existing：验证已有代理（只有分片 0 干活）
阶段 2 common         ：12 探针 + 177 代理（TCP 探活，IP 级短路）+ 顺便代理验证
                        → 输出 open_ips_shardN.txt（所有存活 IP）
                        → 输出 proxy_ips_shardN.txt（有代理的 IP，供 revalidate 用）
阶段 3 revalidate     ：对 proxy_ips_shardN.txt（有代理的 IP）二次探活
阶段 4 proxy          ：177 代理端口（完整扫描 + 单验证，3 协议全试）
阶段 5 full           ：65535 全端口（只扫 proxy 未找到代理的 IP）

验证：单验证 —— 读秀（https://www.duxiu.com/），命中「读秀学术搜索」才算有效代理
代理协议：http / socks5 / socks4（已去掉 https）
★ 终极定版：TCP_TIMEOUT=1.0，CONNECT_TIMEOUT=15，MAX_TIME=30
★ 极限并发：80×25 = 2000 并发（实测 2500 task/s）
★ 彻底取消验证限速（VERIFY_RATE_LIMIT=0），且内嵌验证并发，解决串行卡 35 分钟的问题
★ full 前置探活：全端口前先探 COMMON_PORTS（181个），若全闭直接跳过，防止死 IP 浪费时间
★ 游标切片：按 BATCH_SIZE 切片，无缝换 IP 防止被防火墙封禁
★ 新增发包熔断：按 TOTAL_MAX_REQUESTS 限制，触发立即停止，严防高校防火墙封禁
"""

import os
import re
import sys
import json
import time
import socket
import shutil
import tempfile
import argparse
import subprocess
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============ 核心调度参数（每次换学校请根据需要修改） ============
# 每次触发 Actions 扫描的总 IP 数量（会自动均分给 8 个分片，如 30000 即每分片 3750 个）
BATCH_SIZE = 30000

# 全局总探活次数熔断限额（单分片限额 = TOTAL_MAX_REQUESTS / 8，如 5500000 即单分片 687500 次）
# 如果学校防火墙容易封，可以调小；如果一直没被封且速度很快，可以调大。
TOTAL_MAX_REQUESTS = 5500000
# ===============================================================

CURSOR_FILE = 'scan_cursor.json'
FINISHED_FLAG = 'scan_finished.flag'

# ============ 配置 ============
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

CONNECT_TIMEOUT = 15
MAX_TIME = 30

VERIFY_TARGETS = [
    {
        'name': 'duxiu',
        'urls': ['https://www.duxiu.com/'],
        'keywords': ['读秀学术搜索'],
        'exclude': ['系统登录', '用户名', '密 码', '请完成安全验证'],
        'protocols': ['http', 'socks5', 'socks4'],
    },
]

MAX_RUNTIME_SEC = int(os.environ.get('MAX_RUNTIME_SEC', 20880))

def _build_probe_ports_12():
    return [22, 80, 443, 3389, 1080, 1081, 8080, 8081, 7890, 3128, 8000, 8443]


def _build_proxy_ports():
    groups = [
        (1080, 1090), (10808, 10820), (7890, 7899), (8080, 8090),
        (8000, 8010), (8888, 8890), (9000, 9010), (9090, 9099),
        (10000, 10010), (10080, 10086), (3128, 3130), (8388, 8389),
        (8443, 8444), (2052, 2096), (51820, 51830), (1194, 1199),
        (9050, 9051), (9150, 9151),
        (15732, 15732), (26001, 26001), (29290, 29290),
        (10090, 10090), (17891, 17891), (10792, 10792),
    ]
    s = set()
    for a, b in groups:
        s.update(range(a, b + 1))
    return sorted(s)


def _build_common_ports():
    probe12 = _build_probe_ports_12()
    proxy = _build_proxy_ports()
    seen = set()
    result = []
    for p in probe12:
        if p not in seen:
            seen.add(p)
            result.append(p)
    for p in proxy:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


PROBE_PORTS_12 = _build_probe_ports_12()
PROXY_PORTS = _build_proxy_ports()
COMMON_PORTS = _build_common_ports()
FULL_PORTS = list(range(1, 65536))

parser = argparse.ArgumentParser()
parser.add_argument('--shard', type=int, default=0)
parser.add_argument('--shard-total', type=int, default=1)
args, _ = parser.parse_known_args()

SHARD_INDEX = args.shard
SHARD_TOTAL = args.shard_total

SHARD_MAX_REQUESTS = TOTAL_MAX_REQUESTS // SHARD_TOTAL if SHARD_TOTAL > 0 else TOTAL_MAX_REQUESTS

TCP_TIMEOUT = 1.0
VERIFY_TIMEOUT = 30
VERIFY_RETRY = 0
VERIFY_DELAY = 0.0
TCP_WORKERS = 80
PORT_WORKERS = 25
IP_COOLDOWN = 0.5
VERIFY_RATE_LIMIT = 0

INPUT_FILE = 'ip_list.txt'
PHASE_FILE = 'phase.json'
RUNNER_TEMP = os.environ.get('RUNNER_TEMP', '/tmp')

if SHARD_TOTAL > 1:
    STATE_FILE = 'progress_shard%d.json' % SHARD_INDEX
    OUTPUT_FILE = 'working_proxies_shard%d.txt' % SHARD_INDEX
    OPEN_IPS_FILE = 'open_ips_shard%d.txt' % SHARD_INDEX
    PROXY_IPS_FILE = 'proxy_ips_shard%d.txt' % SHARD_INDEX
    OPEN_IPS_REVALIDATED_FILE = 'open_ips_revalidated_shard%d.txt' % SHARD_INDEX
    PROXY_MISSING_FILE = 'proxy_missing_shard%d.txt' % SHARD_INDEX
else:
    STATE_FILE = 'progress.json'
    OUTPUT_FILE = 'working_proxies.txt'
    OPEN_IPS_FILE = 'open_ips.txt'
    PROXY_IPS_FILE = 'proxy_ips.txt'
    OPEN_IPS_REVALIDATED_FILE = 'open_ips_revalidated.txt'
    PROXY_MISSING_FILE = 'proxy_missing.txt'

CRLF = '\r\n'
EXISTING_PROXIES_FILE = 'working_proxies.txt'
ALIVE_IP_RANGES_FILE = 'alive_ip_ranges.txt'

CURL = shutil.which('curl') or 'curl'
PROTOCOLS = ('http', 'socks5', 'socks4')


def log(msg):
    print(msg, flush=True)


_WS_RE = re.compile(r'\s+')


def _clean_note(s):
    if not s:
        return ''
    s = s.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
    s = s.replace('@', ' ')
    return _WS_RE.sub(' ', s).strip()


QQWRY_RANGE_RE = re.compile(
    r'(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})'
)
SINGLE_IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')


def _valid_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def parse_ip_range(line):
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('@'):
        return None
    
    note = ''
    if '|' in line:
        parts = line.split('|', 1)
        line = parts[0].strip()
        note = _clean_note(parts[1])

    for tok in line.split():
        if '/' in tok:
            try:
                net = ipaddress.ip_network(tok, strict=False)
                if net.version != 4:
                    continue
                return int(net.network_address), int(net.broadcast_address), note
            except Exception:
                pass
                
    m = QQWRY_RANGE_RE.search(line)
    if m:
        a, b = m.group(1), m.group(2)
        if _valid_ipv4(a) and _valid_ipv4(b):
            sa = int(ipaddress.IPv4Address(a))
            sb = int(ipaddress.IPv4Address(b))
            return min(sa, sb), max(sa, sb), note
            
    m = SINGLE_IP_RE.search(line)
    if m:
        a = m.group(1)
        if _valid_ipv4(a):
            return int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(a)), note
            
    return None


def load_ip_ranges(path):
    ranges = []
    with open(path, 'r', encoding='utf-8-sig', errors='ignore') as f:
        for line in f:
            r = parse_ip_range(line)
            if r:
                ranges.append(r)
    return ranges


def expand_ranges_to_ips(ranges):
    flat = []
    for s, e, note in ranges:
        for ip_int in range(s, e + 1):
            flat.append((ip_int, note))
    return flat


def ip_int_to_str(ip_int):
    return str(ipaddress.IPv4Address(ip_int))


def load_existing_proxies(path):
    s = set()
    if not os.path.exists(path):
        return s
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('@') or line.startswith('#'):
                    continue
                if '@' in line:
                    parts = line.split('@')
                    if len(parts) >= 2:
                        s.add('%s:%s' % (parts[0].strip(),
                                         parts[1].strip().lower()))
                elif '#' in line:
                    p = line.split('#', 1)[0].strip()
                    s.add(p)
                else:
                    parts = line.split()
                    if parts:
                        s.add(parts[0])
    except Exception:
        pass
    return s


def load_proxy_list(path):
    result = []
    if not os.path.exists(path):
        return result
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('@') or line.startswith('#'):
                continue
            parts = line.split('@')
            if len(parts) < 2:
                continue
            addr = parts[0].strip()
            proto = parts[1].strip().lower()
            note = '@'.join(parts[2:]).strip() if len(parts) > 2 else ''
            if ':' not in addr:
                continue
            ip, port_str = addr.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                continue
            if proto not in PROTOCOLS:
                continue
            result.append((ip, port, proto, note))
    return result


def load_ip_set(path):
    s = set()
    if not os.path.exists(path):
        return s
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    s.add(line)
    except Exception:
        pass
    return s


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def save_json(path, data):
    try:
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        log('[!] 保存 %s 失败: %s' % (path, e))


_rate_lock = threading.Lock()
_rate_last = [0.0]


def verify_rate_wait():
    if VERIFY_RATE_LIMIT <= 0:
        return
    min_interval = 1.0 / VERIFY_RATE_LIMIT
    while True:
        with _rate_lock:
            now = time.time()
            wait = _rate_last[0] + min_interval - now
            if wait <= 0:
                _rate_last[0] = now
                return
        time.sleep(min(wait, 0.2))


def tcp_check(ip, port, timeout=TCP_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _build_curl_args(ip, port, protocol, url):
    address = '%s:%d' % (ip, port)
    if protocol == 'http':
        return ['-x', address, url]
    if protocol == 'https':
        return ['-x', 'https://' + address, url]
    if protocol == 'socks5':
        return ['--socks5-hostname', address, url]
    if protocol == 'socks4':
        return ['--socks4a', address, url]
    return None


def _text_contains_any(raw, keywords, excludes):
    try:
        text = raw.decode('utf-8', errors='ignore')
    except Exception:
        return False
    if any(ex in text for ex in excludes):
        return False
    if any(kw in text for kw in keywords):
        return True
    return False


def _verify_one_url(ip, port, protocol, url, keywords, excludes):
    args = _build_curl_args(ip, port, protocol, url)
    if args is None:
        return False
    verify_rate_wait()

    cookie_fd, cookie_path = tempfile.mkstemp(prefix='curl_cookie_', suffix='.txt')
    os.close(cookie_fd)

    try:
        cmd = [
            CURL,
            '-sS',
            '-L',
            '--max-redirs', '5',
            '-c', cookie_path,
            '-b', cookie_path,
            '-4',
            '--connect-timeout', str(CONNECT_TIMEOUT),
            '--max-time', str(MAX_TIME),
            '-A', UA,
            '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            '-H', 'Accept-Language: zh-CN,zh;q=0.9,en;q=0.8',
        ] + args
        proc = subprocess.run(cmd, capture_output=True, timeout=MAX_TIME + 3)
        return _text_contains_any(proc.stdout, keywords, excludes)
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False
    finally:
        try:
            if os.path.exists(cookie_path):
                os.remove(cookie_path)
        except Exception:
            pass


def _verify_one_target(ip, port, protocol, target):
    for url in target['urls']:
        if _verify_one_url(ip, port, protocol, url,
                           target['keywords'], target.get('exclude', [])):
            return True
    return False


def verify_proxy(ip, port, protocol):
    for target in VERIFY_TARGETS:
        if protocol not in target.get('protocols', []):
            continue
        if not _verify_one_target(ip, port, protocol, target):
            return False
    return True


def scan_port_common(ip, port):
    return tcp_check(ip, port), []


def scan_port_full(ip, port):
    if not tcp_check(ip, port):
        return False, []
    working = []
    for proto in PROTOCOLS:
        if verify_proxy(ip, port, proto):
            working.append((ip, port, proto))
    return True, working


def get_phase_config(phase):
    if phase == 'common':
        return COMMON_PORTS, None, OPEN_IPS_FILE
    elif phase == 'revalidate':
        return COMMON_PORTS, PROXY_IPS_FILE, OPEN_IPS_REVALIDATED_FILE
    elif phase == 'proxy':
        return PROXY_PORTS, OPEN_IPS_REVALIDATED_FILE, PROXY_MISSING_FILE
    elif phase == 'full':
        return FULL_PORTS, PROXY_MISSING_FILE, None
    else:
        raise ValueError('未知阶段: %s' % phase)


def _skip_this_shard(state_file, output_filter_file, phase, ports_count):
    state = {
        'position': 0, 'done': 0, 'total_ips': 0, 'total_tasks': 0,
        'ports_count': ports_count, 'phase': phase,
        'shard_index': SHARD_INDEX, 'shard_total': SHARD_TOTAL,
        'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'completed': True,
        'completed_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'session': 1,
    }
    save_json(state_file, state)
    if output_filter_file:
        try:
            with open(output_filter_file, 'w', encoding='utf-8', newline='') as f:
                pass
        except Exception:
            pass


def run_verify_existing_phase():
    if SHARD_INDEX != 0:
        log('[verify_existing] 分片 %d 跳过（只有分片 0 做验证）' % SHARD_INDEX)
        _skip_this_shard(STATE_FILE, None, 'verify_existing', 0)
        return

    proxy_list = load_proxy_list(EXISTING_PROXIES_FILE)
    log('[verify_existing] 从 %s 读到 %d 个历史代理'
        % (EXISTING_PROXIES_FILE, len(proxy_list)))

    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
        f.write('@ 代理扫描结果 [verify_existing]' + CRLF)
        f.write('@ 开始时间: %s' % time.strftime('%Y-%m-%d %H:%M:%S') + CRLF)
        f.write('@ 验证: 读秀 https（单验证）' + CRLF)
        f.write('@' + '-' * 58 + CRLF)

    if not proxy_list:
        log('[verify_existing] 无历史代理可验证，跳过')
        state = {
            'position': 0, 'done': 0, 'total_ips': 0, 'total_tasks': 0,
            'ports_count': 0, 'phase': 'verify_existing',
            'shard_index': 0, 'shard_total': SHARD_TOTAL,
            'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'completed': True,
            'completed_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'session': 1,
        }
        save_json(STATE_FILE, state)
        return

    valid_count = [0]
    checked_count = [0]
    found_lock = threading.Lock()
    t0 = time.time()

    def verify_one(item):
        ip, port, proto, note = item
        ok = verify_proxy(ip, port, proto)
        with found_lock:
            checked_count[0] += 1
            n = checked_count[0]
            if ok:
                valid_count[0] += 1
                if note:
                    line_out = '%s:%d@%s@%s' % (ip, port, proto, note)
                else:
                    line_out = '%s:%d@%s' % (ip, port, proto)
                with open(OUTPUT_FILE, 'a', encoding='utf-8', newline='') as f:
                    f.write(line_out + CRLF)
                log('[+] 仍然有效: %s' % line_out)
            else:
                log('[-] 已失效: %s:%d@%s' % (ip, port, proto))
            if n % 20 == 0:
                elapsed = time.time() - t0
                log('[verify_existing] 已检查 %d/%d | 有效 %d | %.1f s'
                    % (n, len(proxy_list), valid_count[0], elapsed))

    port_pool = ThreadPoolExecutor(max_workers=TCP_WORKERS * PORT_WORKERS)
    try:
        futures = [port_pool.submit(verify_one, item) for item in proxy_list]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as ex:
                log('[!] verify_one 异常: %s' % ex)
    finally:
        port_pool.shutdown(wait=False)

    dt = time.time() - t0
    log('=' * 60)
    log('[verify_existing] 验证完成: %d/%d 仍然有效，耗时 %.1f 秒'
        % (valid_count[0], len(proxy_list), dt))

    state = {
        'position': len(proxy_list),
        'done': len(proxy_list),
        'total_ips': len(proxy_list),
        'phase': 'verify_existing',
        'shard_index': 0, 'shard_total': SHARD_TOTAL,
        'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'completed': True,
        'completed_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'session': 1,
    }
    save_json(STATE_FILE, state)


def main():
    if not os.path.exists(INPUT_FILE):
        log('未找到 %s' % INPUT_FILE)
        sys.exit(1)

    phase_state = load_json(PHASE_FILE) or {
        'current': 'common',
        'common_completed': False,
        'revalidate_completed': False,
        'proxy_completed': False,
        'full_completed': False,
    }
    current_phase = phase_state.get('current', 'common')

    if current_phase == 'verify_existing':
        run_verify_existing_phase()
        return

    all_ranges = load_ip_ranges(INPUT_FILE)
    if not all_ranges:
        log('未读取到有效 IP 范围')
        sys.exit(1)

    # ★ 展开所有 IP，根据游标切片
    all_ips_flat = expand_ranges_to_ips(all_ranges)
    total_all_ips = len(all_ips_flat)
    
    cursor_state = load_json(CURSOR_FILE) or {'offset': 0}
    current_offset = cursor_state.get('offset', 0)
    
    PORTS, upstream_file, output_filter_file = get_phase_config(current_phase)

    if current_offset >= total_all_ips:
        log('游标 %d >= 总IP数 %d，全部扫描完毕。' % (current_offset, total_all_ips))
        if SHARD_INDEX == 0:
            with open(FINISHED_FLAG, 'w') as f:
                f.write('yes')
        _skip_this_shard(STATE_FILE, output_filter_file, current_phase, 0)
        return

    batch_end = min(current_offset + BATCH_SIZE, total_all_ips)
    batch_ips = all_ips_flat[current_offset:batch_end]
    log('当前批次游标: %d ~ %d，本批次共 %d 个 IP' % (current_offset, batch_end, len(batch_ips)))

    # 按分片切分这批 IP
    total_in_batch = len(batch_ips)
    shard_size = (total_in_batch + SHARD_TOTAL - 1) // SHARD_TOTAL
    lo = SHARD_INDEX * shard_size
    hi = min(lo + shard_size, total_in_batch)
    my_ips = batch_ips[lo:hi]
    
    ip_list = my_ips

    if upstream_file is not None:
        if os.path.exists(upstream_file):
            wanted = load_ip_set(upstream_file)
            if wanted:
                before = len(ip_list)
                ip_list = [(ip_int, note) for (ip_int, note) in ip_list if ip_int_to_str(ip_int) in wanted]
                log('[%s] 上游过滤 (%s): %d → %d'
                    % (current_phase, upstream_file, before, len(ip_list)))
                if current_phase == 'revalidate':
                    ip_note_map = {}
                    for ip_int, note in my_ips:
                        if note:
                            ip_note_map[ip_int] = note
                    ip_list = [(ip_int, ip_note_map.get(ip_int, '')) for ip_int, _ in ip_list]
            else:
                log('[%s] 上游文件为空，本片无待扫 IP，跳过' % current_phase)
                _skip_this_shard(STATE_FILE, output_filter_file, current_phase, len(PORTS))
                return
        else:
            log('[%s] 无上游文件 %s，视为无待扫 IP，本片跳过'
                % (current_phase, upstream_file))
            _skip_this_shard(STATE_FILE, output_filter_file, current_phase, len(PORTS))
            return

    total_ips = len(ip_list)

    def ip_at_position(pos):
        return ip_list[pos]

    state = load_json(STATE_FILE)
    new_round = True
    if (state and not state.get('completed')
            and state.get('total_ips') == total_ips
            and state.get('phase') == current_phase):
        new_round = False

    if new_round:
        state = {
            'position': 0, 'done': 0, 'total_ips': total_ips,
            'phase': current_phase, 'shard_index': SHARD_INDEX,
            'shard_total': SHARD_TOTAL,
            'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'completed': False, 'session': 1,
        }
        with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
            f.write('@ 代理扫描结果 [分片 %d/%d, 阶段 %s]'
                    % (SHARD_INDEX, SHARD_TOTAL, current_phase) + CRLF)
            f.write('@ 开始时间: %s' % state['started_at'] + CRLF)
            f.write('@ 验证: 读秀 https（单验证）' + CRLF)
            f.write('@' + '-' * 58 + CRLF)
        existing = set()
        log('=== 新一轮扫描 [分片 %d/%d, phase=%s] ==='
            % (SHARD_INDEX, SHARD_TOTAL, current_phase))

        if SHARD_INDEX == 0:
            try:
                if os.path.exists(ALIVE_IP_RANGES_FILE):
                    os.remove(ALIVE_IP_RANGES_FILE)
                    log('已清空上一轮的 %s' % ALIVE_IP_RANGES_FILE)
            except Exception:
                pass
    else:
        state['session'] = state.get('session', 1) + 1
        existing = load_existing_proxies(OUTPUT_FILE)
        log('=== 续跑 [分片 %d/%d, phase=%s, session %d] ==='
            % (SHARD_INDEX, SHARD_TOTAL, current_phase, state['session']))
        log('上次位置: %d / %d (%.1f%%)'
            % (state['position'], total_ips,
               state['position'] * 100.0 / total_ips if total_ips else 0))

    start_position = state['position']

    # ★ 读取全局累积数据，用于日志展示
    history_alive_count = 0
    if os.path.exists('alive_ips.txt'):
        try:
            with open('alive_ips.txt', 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.strip() and not line.startswith('@'):
                        history_alive_count += 1
        except Exception:
            pass
            
    global_proxy_count = 0
    if os.path.exists('working_proxies.txt'):
        try:
            with open('working_proxies.txt', 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.strip() and not line.startswith('@'):
                        global_proxy_count += 1
        except Exception:
            pass

    log('本片 IP 总数: %d' % total_ips)
    log('端口数: %d' % len(PORTS))
    if current_phase in ('common', 'revalidate'):
        log('  前 12 探针: %s' % PROBE_PORTS_12)
    
    # ★ 日志展示全量视角
    log('本次起点: 本片 IP #%d (全局游标 #%d / 总 %d)' % (state['position'], current_offset, total_all_ips))
    log('已找到代理: 全局累积 %d 个 | 本片已有 %d 个' % (global_proxy_count, len(existing)))
    log('历史存活 IP 累积: %d 个' % history_alive_count)
    
    log('搜索连接超时: %s s | 验证超时: %d s' % (TCP_TIMEOUT, VERIFY_TIMEOUT))
    log('IP 并发: %d  ×  端口并发: %d  =  全局最大 %d 条连接'
        % (TCP_WORKERS, PORT_WORKERS, TCP_WORKERS * PORT_WORKERS))
    log('验证方式: curl (%s)' % CURL)
    for t in VERIFY_TARGETS:
        log('  验证目标 [%s]: %s | 适用协议: %s | 关键词: %s | 排除: %s'
            % (t['name'], t['urls'], t.get('protocols', ['?']),
               t['keywords'], t.get('exclude', [])))
    log('成功判定: 命中读秀页面（单验证）')
    log('验证协议: %s（不短路，全试）' % (', '.join(PROTOCOLS)))
    log('curl 超时: 连接 %d s / 总 %d s' % (CONNECT_TIMEOUT, MAX_TIME))
    
    if VERIFY_RATE_LIMIT > 0:
        log('全局限速: %d 次/秒（全局串行排队控制）' % VERIFY_RATE_LIMIT)
    else:
        log('全局限速: 无限制（完全依据发现速度瞬间并发，不排队）')

    log('最大运行时长: %d 秒 (%.2f 小时)'
        % (MAX_RUNTIME_SEC, MAX_RUNTIME_SEC / 3600.0))
    log('发包熔断限额: %d 次/分片（全局 %d 次）'
        % (SHARD_MAX_REQUESTS, TOTAL_MAX_REQUESTS))
    log('-' * 60)

    pos_lock = threading.Lock()
    current_pos = [state['position']]
    found_lock = threading.Lock()
    found_count = [len(existing)]
    processed_ips = [0]
    port_tasks = [0]
    stop_flag = [False]
    t0 = time.time()

    open_ips_lock = threading.Lock()
    open_ips = set()
    proxy_ips = set()
    revalidated_ips = set()
    proxy_found_ips = set()
    proxy_missing_ips = set()

    def next_position():
        with pos_lock:
            if current_pos[0] >= total_ips:
                return None
            p = current_pos[0]
            current_pos[0] += 1
            return p

    port_pool = ThreadPoolExecutor(max_workers=TCP_WORKERS * PORT_WORKERS)
    if current_phase in ('common', 'revalidate'):
        scan_fn = scan_port_common
        short_circuit = True
    else:
        scan_fn = scan_port_full
        short_circuit = False

    def worker():
        while not stop_flag[0]:
            p = next_position()
            if p is None:
                return
            ip_int, note = ip_at_position(p)
            ip = ip_int_to_str(ip_int)

            ip_has_open = False
            ip_has_proxy = False
            ip_open_count = 0
            ip_proxy_count = 0

            if current_phase == 'full':
                ip_alive = False
                probe_futures = [port_pool.submit(tcp_check, ip, port) for port in COMMON_PORTS]
                for pf in as_completed(probe_futures):
                    if pf.result():
                        ip_alive = True
                        break
                if not ip_alive:
                    with found_lock:
                        processed_ips[0] += 1
                        real_done = start_position + processed_ips[0]
                        pct = real_done * 100.0 / total_ips if total_ips else 0
                        elapsed = time.time() - t0
                        log('[full] IP %s 探活失败 (181端口全闭)，跳过全端口 | 全局 %d/%d (%.2f%%) | %.0f s'
                            % (ip, real_done, total_ips, pct, elapsed))
                    continue

            futures = []
            for port in PORTS:
                all_done = True
                for proto in PROTOCOLS:
                    if '%s:%d:%s' % (ip, port, proto) not in existing:
                        all_done = False
                        break
                if all_done:
                    continue
                futures.append((port, port_pool.submit(scan_fn, ip, port)))

            total_ports_for_ip = len(futures)
            processed_ports_for_ip = 0

            for port, fut in futures:
                if stop_flag[0]:
                    return
                try:
                    is_open, r_list = fut.result()
                except Exception:
                    is_open, r_list = False, []
                if is_open:
                    ip_has_open = True
                    ip_open_count += 1
                if r_list:
                    ip_has_proxy = True
                    for item in r_list:
                        ip_, port_, proto_ = item
                        key = '%s:%d:%s' % (ip_, port_, proto_)
                        with found_lock:
                            if key in existing:
                                continue
                            existing.add(key)
                            found_count[0] += 1
                            ip_proxy_count += 1
                            if note:
                                line_out = '%s:%d@%s@%s' % (ip_, port_, proto_, note)
                            else:
                                line_out = '%s:%d@%s' % (ip_, port_, proto_)
                            with open(OUTPUT_FILE, 'a', encoding='utf-8', newline='') as f:
                                f.write(line_out + CRLF)
                            log('[+] ' + line_out)
                with found_lock:
                    port_tasks[0] += 1
                    processed_ports_for_ip += 1
                    
                    # ★ 发包熔断检查
                    if port_tasks[0] >= SHARD_MAX_REQUESTS and not stop_flag[0]:
                        log('[!] 单分片探活次数达到 %d，触发换 IP 熔断！' % SHARD_MAX_REQUESTS)
                        stop_flag[0] = True
                        current_pos[0] = total_ips
                        return
                        
                    if current_phase == 'full' and processed_ports_for_ip % 5000 == 0:
                        elapsed = time.time() - t0
                        ppct = processed_ports_for_ip * 100.0 / total_ports_for_ip if total_ports_for_ip else 0
                        log('[full] %s 端口 %d/%d (%.1f%%) | 开放 %d | 本片代理 %d | %.0f s'
                            % (ip, processed_ports_for_ip, total_ports_for_ip,
                               ppct, ip_open_count, found_count[0], elapsed))
                if short_circuit and ip_has_open:
                    break

            if current_phase == 'common' and ip_has_open:
                verify_futures = []
                for port in PROXY_PORTS:
                    verify_futures.append(port_pool.submit(scan_port_full, ip, port))
                
                for fut in as_completed(verify_futures):
                    if stop_flag[0]:
                        return
                    try:
                        _, r_list2 = fut.result()
                    except Exception:
                        r_list2 = []
                    
                    if r_list2:
                        ip_has_proxy = True
                        for item in r_list2:
                            ip_, port_, proto_ = item
                            key = '%s:%d:%s' % (ip_, port_, proto_)
                            with found_lock:
                                if key in existing:
                                    continue
                                existing.add(key)
                                found_count[0] += 1
                                ip_proxy_count += 1
                                if note:
                                    line_out = '%s:%d@%s@%s' % (ip_, port_, proto_, note)
                                else:
                                    line_out = '%s:%d@%s' % (ip_, port_, proto_)
                                with open(OUTPUT_FILE, 'a', encoding='utf-8', newline='') as f:
                                    f.write(line_out + CRLF)
                                log('[★] [common] 发现有效代理: ' + line_out)

            if current_phase == 'common':
                if ip_has_open:
                    with open_ips_lock:
                        open_ips.add(ip)
                if ip_has_proxy:
                    with open_ips_lock:
                        proxy_ips.add(ip)
            elif current_phase == 'revalidate':
                if ip_has_open:
                    with open_ips_lock:
                        revalidated_ips.add(ip)
            elif current_phase == 'proxy':
                with open_ips_lock:
                    if ip_has_proxy:
                        proxy_found_ips.add(ip)
                    else:
                        proxy_missing_ips.add(ip)

            with found_lock:
                processed_ips[0] += 1
                real_done = start_position + processed_ips[0]
                pct = real_done * 100.0 / total_ips if total_ips else 0
                if current_phase == 'full':
                    elapsed = time.time() - t0
                    speed = port_tasks[0] / elapsed if elapsed > 0 else 0
                    log('[full] IP #%d %s 扫完 | 本 IP: 端口开放 %d, 代理 %d | 全局 %d/%d (%.2f%%) | 累计代理 %d | %.1f task/s | %.0f s'
                        % (real_done, ip, ip_open_count, ip_proxy_count,
                           real_done, total_ips, pct,
                           found_count[0], speed, elapsed))
                elif processed_ips[0] % 200 == 0:
                    elapsed = time.time() - t0
                    speed = port_tasks[0] / elapsed if elapsed > 0 else 0
                    with open_ips_lock:
                        oc = len(open_ips)
                        pc = len(proxy_ips)
                        rc = len(revalidated_ips)
                        pf = len(proxy_found_ips)
                        pm = len(proxy_missing_ips)
                    if current_phase == 'common':
                        extra = '存活 %d (累计 %d) | 代理IP %d (累计 %d)' % (oc, history_alive_count + oc, pc, global_proxy_count + found_count[0] - len(existing) + pc)
                    elif current_phase == 'revalidate':
                        extra = '重验存活 %d' % rc
                    elif current_phase == 'proxy':
                        extra = '找到 %d | 待深扫 %d' % (pf, pm)
                    else:
                        extra = ''
                    log('[进度] 已处理 %d/%d IP | 全局 %.2f%% | %s | %.1f task/s | %.0f s'
                        % (real_done, total_ips, pct, extra, speed, elapsed))

            if IP_COOLDOWN > 0:
                time.sleep(IP_COOLDOWN)

    def watchdog():
        while not stop_flag[0]:
            if time.time() - t0 > MAX_RUNTIME_SEC:
                log('[!] 达到最大运行时长，优雅停止')
                stop_flag[0] = True
                return
            time.sleep(5)

    threading.Thread(target=watchdog, daemon=True).start()

    try:
        with ThreadPoolExecutor(max_workers=TCP_WORKERS) as ip_pool:
            futures = [ip_pool.submit(worker) for _ in range(TCP_WORKERS)]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as ex:
                    log('[!] worker 异常: %s' % ex)
    finally:
        stop_flag[0] = True
        port_pool.shutdown(wait=False)

    with pos_lock:
        state['position'] = current_pos[0]
    state['done'] = state.get('done', 0) + port_tasks[0]

    if state['position'] >= total_ips:
        state['completed'] = True
        state['completed_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
        log('=' * 60)
        log('[分片 %d/%d, 阶段 %s] 本阶段本片扫描完成！'
            % (SHARD_INDEX, SHARD_TOTAL, current_phase))
    else:
        log('=' * 60)
        log('[分片 %d/%d, 阶段 %s] 本次 session 结束，剩余 %d 个 IP'
            % (SHARD_INDEX, SHARD_TOTAL, current_phase,
               total_ips - state['position']))

    if current_phase == 'common' and open_ips:
        try:
            existing_open = load_ip_set(OPEN_IPS_FILE)
            existing_open.update(open_ips)
            with open(OPEN_IPS_FILE, 'w', encoding='utf-8', newline='') as f:
                for ip in sorted(existing_open):
                    f.write(ip + CRLF)
            log('本 session 存活 IP: %d 个' % len(open_ips))
            log('存活 IP 列表已更新: %s (本 session %d, 累计 %d)'
                % (OPEN_IPS_FILE, len(open_ips), len(existing_open)))
        except Exception as e:
            log('[!] 写存活 IP 文件失败: %s' % e)

        try:
            existing_proxy_ips = load_ip_set(PROXY_IPS_FILE)
            existing_proxy_ips.update(proxy_ips)
            with open(PROXY_IPS_FILE, 'w', encoding='utf-8', newline='') as f:
                for ip in sorted(existing_proxy_ips):
                    f.write(ip + CRLF)
            log('本 session 有代理的 IP: %d 个' % len(proxy_ips))
            log('代理 IP 列表已更新: %s (本 session %d, 累计 %d)'
                % (PROXY_IPS_FILE, len(proxy_ips), len(existing_proxy_ips)))
        except Exception as e:
            log('[!] 写代理 IP 文件失败: %s' % e)

    elif current_phase == 'revalidate' and revalidated_ips:
        try:
            existing_rev = load_ip_set(OPEN_IPS_REVALIDATED_FILE)
            existing_rev.update(revalidated_ips)
            with open(OPEN_IPS_REVALIDATED_FILE, 'w', encoding='utf-8', newline='') as f:
                for ip in sorted(existing_rev):
                    f.write(ip + CRLF)
            log('本 session 重验存活 IP: %d 个' % len(revalidated_ips))
            log('重验存活列表已更新: %s (本 session %d, 累计 %d)'
                % (OPEN_IPS_REVALIDATED_FILE, len(revalidated_ips), len(existing_rev)))
        except Exception as e:
            log('[!] 写重验存活文件失败: %s' % e)

    elif current_phase == 'proxy' and proxy_missing_ips:
        try:
            existing_missing = load_ip_set(PROXY_MISSING_FILE)
            existing_missing.update(proxy_missing_ips)
            with open(PROXY_MISSING_FILE, 'w', encoding='utf-8', newline='') as f:
                for ip in sorted(existing_missing):
                    f.write(ip + CRLF)
            log('本 session 找到代理的 IP: %d 个' % len(proxy_found_ips))
            log('本 session 待深扫 IP: %d 个' % len(proxy_missing_ips))
            log('待深扫列表已更新: %s (本 session %d, 累计 %d)'
                % (PROXY_MISSING_FILE, len(proxy_missing_ips), len(existing_missing)))
        except Exception as e:
            log('[!] 写待深扫文件失败: %s' % e)

    save_json(STATE_FILE, state)

    dt = time.time() - t0
    log('-' * 60)
    log('本 session 耗时: %.1f 秒 (%.2f 小时)' % (dt, dt / 3600.0))
    log('累计找到代理: %d' % found_count[0])
    log('本片进度: %d/%d (%.1f%%)'
        % (state['position'], total_ips,
           state['position'] * 100.0 / total_ips if total_ips else 0))


if __name__ == '__main__':
    main()
