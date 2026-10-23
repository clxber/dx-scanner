# -*- coding: utf-8 -*-
"""
高校代理扫描器 —— 五阶段 + 分片 + 断点续跑

阶段 1 verify_existing：验证已有代理（只有分片 0 干活）
阶段 2 common         ：12 探针 + 176 代理（TCP 探活，IP 级短路）+ 顺便代理验证
                        → 输出 open_ips_shardN.txt（所有存活 IP）
                        → 输出 proxy_ips_shardN.txt（有代理的 IP，供 revalidate 用）
阶段 3 revalidate     ：对 proxy_ips_shardN.txt（有代理的 IP）二次探活
阶段 4 proxy          ：176 代理端口（完整扫描 + 单验证，3 协议全试）
阶段 5 full           ：65535 全端口（只扫 proxy 未找到代理的 IP）

验证：单验证 —— 读秀（https://www.duxiu.com/），命中「读秀学术搜索」才算有效代理
代理协议：http / socks5 / socks4（已去掉 https）
★ 终极定版：TCP_TIMEOUT=1.0，CONNECT_TIMEOUT=5，MAX_TIME=8 (防假死极速超时)
★ 极限并发：TCP 80×25 = 2000 并发，日常 curl 150 并发（防 CPU 爆炸），收尾阶段动态扩至 400 并发！
★ 彻底取消验证限速（VERIFY_RATE_LIMIT=0），且内嵌验证并发，解决串行卡 35 分钟的问题
★ full 前置探活：全端口前先探 COMMON_PORTS（188个），若全闭直接跳过，防止死 IP 浪费时间
★ 全端口开拔前置过滤：进入 full 阶段时，一次性并发探活所有待深扫 IP，剔除死 IP 后再进行 10 个一批的接力
★ 游标切片：按 BATCH_SIZE 切片，无缝换 IP 防止被防火墙封禁
★ full 游标切片：按 FULL_BATCH_SIZE=10 切片，单次扫 65 万次，彻底杜绝熔断误伤
★ 新增发包熔断：按 TOTAL_MAX_REQUESTS 限制，触发立即停止，严防高校防火墙封禁
★ 无缝接力：熔断触发时不再强行标记本片完成，且 full 阶段只有整批扫完才推进游标，彻底消灭漏扫
★ 兄弟分片联动：若本分片在当前批次已 100% 完成，下一轮启动时直接秒退，绝不陪跑重扫
★ 草稿纸保护：秒退时绝对不覆盖清空已有的存活 IP 记录，保证数据只增不减
★ 验证诊断：verify_existing 阶段打印详细的中文失败原因，一眼看出是代理挂了、超时、还是被读秀WAF拦截
★ Bug 修复：游标切片仅对 common 阶段生效，revalidate/proxy/full 直接读上游文件，彻底杜绝游标死锁
★ 参数全动态：BATCH_SIZE、FULL_BATCH_SIZE、TOTAL_MAX_REQUESTS 全部支持从环境变量读取
★ Bug 修复：使用 f_offset 对 full 阶段进行指纹校验，防止每批固定 IP 数引起的断点续跑错乱
★ 终极防御：使用 c_offset 对 common 阶段也进行指纹校验，彻底杜绝任何因为清理失败导致的秒退跳过
★ 文案优化：将新切片日志精准区分为"批次扫描"，消除进度清零的误解
★ 视觉归零：当全局游标为 0 时，日志展示的历史累积 IP 强制归零，契合"重头开始"的直觉
★ 性能重构：full 阶段采用滑动窗口分批提交（每次 5000 个端口），既压满 2000 并发，又防止内存/GIL假死
★ 战利品入库：将中科大实测有效端口 3123 加入常用代理端口池
★ 神来一笔：full 开拔前置全量探活 —— 进入 full 阶段时一次性用 1000 并发把上游全部待深扫 IP 的
  188 个常用端口探一遍，几秒钟剔除死 IP，生成纯净的 full_alive_shardN.txt 存活名单，再用这份
  名单去跑 10 个一批的接力深扫，省下海量 GitHub Actions 接力轮次与运行额度。幂等：文件存在即复用。
★ 自动分片切分：当处于 full 阶段且 proxy_missing_shardN.txt 不存在时，自动读取全局 alive_ips.txt
  并按 1/8 均分生成对应分片文件，省去手动切分文件的痛苦，也省去了为了触发代码自动切分而重置游标重跑 common 阶段的麻烦！
★ 游标稳定性重构：游标底座永远锁定为 proxy_missing_shardN.txt，绝不因为探活结果变化而导致游标错位。
  前置探活结果 full_alive_shardN.txt 仅作为“通行证”，切出来的 IP 若在通行证外，直接秒跳，游标依然稳定推进。
  同时引入 load_ip_list 强制排序，彻底消除 set 无序导致的随机切片 Bug。
★ 双时间熔断：
  - common / revalidate / proxy 阶段：单 IP 超过 60 秒（MAX_IP_TIME_COMMON）直接熔断。
  - full 阶段：单 IP 超过 300 秒（MAX_IP_TIME_FULL）直接熔断。
★ 彻底分离线程池与动态扩容收尾：
  - port_pool：2000 并发，只跑 tcp_check，速度起飞。
  - verify_pool：日常 150 并发（峰值 450 个 curl），防止 4 核机器被数千个 curl 进程撑爆内存假死。
  - Graceful Shutdown：主线程结束后，若剩余任务过多，立刻拉起 400 并发临时池（峰值 1200 个 curl），光速收尾，绝不漏数据。
★ 千万级 IP 终极防 OOM 重构：
  废弃了 expand_ranges_to_ips 的整段展开列表，改为【按需流式切片】（get_ips_slice）。
  无论 ip_list.txt 有几千万个 IP，内存占用永远只有 BATCH_SIZE 那么大，彻底根绝 Runner 内存溢出。
★ 3 协议并发与 proxy 阶段分流（防 OOM）：
  scan_port_full 内部原本是 3 个协议串行（33 秒）。
  现在：
    - full 阶段和收尾阶段：开 3 个线程并发测 http/socks5/socks4，最坏 11 秒，
      完美适配 full 阶段外层 13 秒超时，解决"慢速 socks 代理被 outer timeout 截断漏掉"的问题。
    - proxy 阶段：保持 3 协议串行（concurrent=False），最坏 33 秒，外层超时放宽到 40 秒兜住。
      原因：proxy 阶段走 2000 并发的 port_pool，若内部再并发会瞬间 6000 个 curl，直接 OOM。
  这样完美兼顾防漏和防炸。
★ proxy 阶段超时放宽：
  因为 proxy 阶段走的是串行 3 协议（最坏 33 秒），如果外层还按 3 秒超时，会把第 2、3 个慢速协议掐死。
  所以 proxy 阶段的外层 fut.result 超时被放宽到 40 秒，配合 MAX_IP_TIME_COMMON=60 秒兜底，完美兜住所有慢速代理。
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
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

# ============ 核心调度参数（自动从环境变量读取，如果没有则用默认值） ============
BATCH_SIZE = int(os.environ.get('BATCH_SIZE', 30000))
FULL_BATCH_SIZE = int(os.environ.get('FULL_BATCH_SIZE', 10))
TOTAL_MAX_REQUESTS = int(os.environ.get('TOTAL_MAX_REQUESTS', 5500000))
# =================================================================================

CURSOR_FILE = 'scan_cursor.json'
FINISHED_FLAG = 'scan_finished.flag'

# ============ 配置 ============
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
CONNECT_TIMEOUT = 5
MAX_TIME = 8
MAX_IP_TIME_COMMON = 60   # ★ common / revalidate / proxy 阶段：单 IP 最大耗时 60 秒
MAX_IP_TIME_FULL = 300    # ★ full 阶段：单 IP 最大耗时 300 秒(5分钟)

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
        (8429, 8429), (10684, 10684), (16699, 16699),
        (8902, 8902), (18080, 18080), (17897, 17897),
        (3123, 3123),
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
VERIFY_WORKERS = 150   # ★ 日常 curl 验证池并发（3 协议并发后，峰值 450 个 curl）
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
    FULL_CURSOR_FILE = 'full_cursor_shard%d.json' % SHARD_INDEX
    FULL_ALIVE_FILE = 'full_alive_shard%d.txt' % SHARD_INDEX
else:
    STATE_FILE = 'progress.json'
    OUTPUT_FILE = 'working_proxies.txt'
    OPEN_IPS_FILE = 'open_ips.txt'
    PROXY_IPS_FILE = 'proxy_ips.txt'
    OPEN_IPS_REVALIDATED_FILE = 'open_ips_revalidated.txt'
    PROXY_MISSING_FILE = 'proxy_missing.txt'
    FULL_CURSOR_FILE = 'full_cursor.json'
    FULL_ALIVE_FILE = 'full_alive.txt'

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


# ★ 终极防 OOM 核心：流式按需切片
def get_ips_slice(ranges, start_idx, end_idx):
    """根据范围列表，只提取游标对应的这一小段 IP（不展开整个 6500 万列表）"""
    flat = []
    current_idx = 0
    for s, e, note in ranges:
        count = e - s + 1
        # 如果当前范围在目标切片结束之后，直接跳出
        if current_idx >= end_idx:
            break
        # 如果当前范围在目标切片开始之前，直接跳过
        if current_idx + count <= start_idx:
            current_idx += count
            continue
        
        # 计算重叠部分
        overlap_start = max(s, s + (start_idx - current_idx))
        overlap_end = min(e, s + (end_idx - current_idx - 1))
        
        for ip_int in range(overlap_start, overlap_end + 1):
            flat.append((ip_int, note))
            
        current_idx += count
    return flat


def get_total_ips_count(ranges):
    """纯数学计算总 IP 数，不展开列表"""
    return sum(e - s + 1 for s, e, n in ranges)


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
    """仅用于不关心顺序的场景，比如判断某个 IP 是否在集合内"""
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


def load_ip_list(path):
    """★ 核心稳定性修复：用于游标切片的场景，必须保证列表有序，绝不能是 set"""
    s = set()
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    s.add(line)
    except Exception:
        pass
    return sorted(list(s))


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


def _verify_one_url(ip, port, protocol, url, keywords, excludes):
    args = _build_curl_args(ip, port, protocol, url)
    if args is None:
        return False, "args_error"
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
        
        if proc.returncode != 0:
            return False, "curl_fail_%d" % proc.returncode
            
        text = proc.stdout.decode('utf-8', errors='ignore')
        if not text:
            return False, "empty_body"
            
        if any(ex in text for ex in excludes):
            return False, "blocked_by_waf"
            
        if any(kw in text for kw in keywords):
            return True, "ok"
            
        snippet = text[:30].replace('\n', ' ').replace('\r', ' ')
        return False, "no_keyword: %s" % snippet
        
    except subprocess.TimeoutExpired:
        return False, "curl_timeout"
    except Exception as e:
        return False, "exception"
    finally:
        try:
            if os.path.exists(cookie_path):
                os.remove(cookie_path)
        except Exception:
            pass


def _verify_one_target(ip, port, protocol, target):
    for url in target['urls']:
        ok, reason = _verify_one_url(ip, port, protocol, url,
                           target['keywords'], target.get('exclude', []))
        if ok:
            return True, reason
    return False, reason


def verify_proxy(ip, port, protocol):
    for target in VERIFY_TARGETS:
        if protocol not in target.get('protocols', []):
            continue
        ok, reason = _verify_one_target(ip, port, protocol, target)
        if not ok:
            return False, reason
    return True, "ok"


def scan_port_common(ip, port):
    return tcp_check(ip, port), []


def scan_port_full(ip, port, concurrent=True):
    if not tcp_check(ip, port):
        return False, []
    
    working = []
    
    def _test_proto(proto):
        ok, _ = verify_proxy(ip, port, proto)
        if ok:
            return (ip, port, proto)
        return None
        
    if not concurrent:
        # ★ proxy 阶段：串行 3 协议，最坏 33s，但不会堆积 3 倍 curl
        for p in PROTOCOLS:
            res = _test_proto(p)
            if res:
                working.append(res)
        return True, working

    # ★ full 阶段和收尾阶段：3 协议并发，避免单个慢协议拖垮整体
    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = [pool.submit(_test_proto, p) for p in PROTOCOLS]
        for f in as_completed(futs):
            res = f.result()
            if res:
                working.append(res)
                
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
        pass


def _translate_reason(reason):
    if not reason:
        return "未知"
    if reason.startswith('curl_fail_7'):
        return "连接失败(代理已死或端口关闭)"
    if reason.startswith('curl_fail_28') or reason == 'curl_timeout':
        return "连接超时(代理半死或网络极慢)"
    if reason.startswith('curl_fail_56'):
        return "连接被重置(可能被中间网关拦截)"
    if reason.startswith('curl_fail_35'):
        return "SSL握手失败(代理不支持CONNECT)"
    if reason.startswith('curl_fail_'):
        return "网络错误(错误码:%s)" % reason.split('_')[-1]
    if reason == 'blocked_by_waf':
        return "命中安全验证(被读秀WAF风控拦截)"
    if reason == 'empty_body':
        return "返回内容为空(可能被反爬拦截)"
    if reason.startswith('no_keyword:'):
        snippet = reason.split(':', 1)[1].strip()
        return "页面无关键词(可能改版或被劫持) [%s...]" % snippet
    if reason == 'args_error':
        return "代理协议配置错误"
    return reason


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
        ok, reason = verify_proxy(ip, port, proto)
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
                cn_reason = _translate_reason(reason)
                log('[-] 已失效: %s:%d@%s (原因: %s)' % (ip, port, proto, cn_reason))
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

    PORTS, upstream_file, output_filter_file = get_phase_config(current_phase)

    # ============ ★ 自动分片切分 ============
    if current_phase == 'full' and upstream_file is not None:
        if not os.path.exists(upstream_file) and os.path.exists('alive_ips.txt'):
            log('[full] 发现上游分片文件 %s 不存在，但检测到全局 alive_ips.txt，自动按分片切分...' % upstream_file)
            global_alive = []
            with open('alive_ips.txt', 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('@'):
                        continue
                    ip_str = line.split('|')[0].strip()
                    global_alive.append(ip_str)
            
            if global_alive:
                shard_size = (len(global_alive) + SHARD_TOTAL - 1) // SHARD_TOTAL
                lo = SHARD_INDEX * shard_size
                hi = min(lo + shard_size, len(global_alive))
                my_ips = global_alive[lo:hi]
                with open(upstream_file, 'w', encoding='utf-8', newline='') as f:
                    for ip in my_ips:
                        f.write(ip + CRLF)
                log('[full] 自动切分完成！本片分得 %d 个 IP，已保存至 %s' % (len(my_ips), upstream_file))

    # ============ ★ 神来一笔：full 阶段开拔前置全量探活 ============
    full_alive_set = None
    if current_phase == 'full' and upstream_file is not None:
        if not os.path.exists(FULL_ALIVE_FILE):
            log('[full] 发现未过滤的深扫名单，开始启动 188 端口全量前置探活...')
            wanted_for_probe = load_ip_list(upstream_file)
            if wanted_for_probe:
                def check_ip_alive(w_ip):
                    for p in COMMON_PORTS:
                        if tcp_check(w_ip, p, timeout=0.5):
                            return True
                    return False

                alive_list = []
                t_start = time.time()
                with ThreadPoolExecutor(max_workers=1000) as executor:
                    futures = {executor.submit(check_ip_alive, ip): ip for ip in wanted_for_probe}
                    for fut in as_completed(futures):
                        w_ip = futures[fut]
                        try:
                            if fut.result():
                                alive_list.append(w_ip)
                        except Exception:
                            pass
                
                with open(FULL_ALIVE_FILE, 'w', encoding='utf-8', newline='') as f:
                    for w_ip in alive_list:
                        f.write(w_ip + CRLF)
                
                log('[full] 前置探活完成！存活 %d/%d 个，耗时 %.1f 秒' 
                    % (len(alive_list), len(wanted_for_probe), time.time() - t_start))
            else:
                with open(FULL_ALIVE_FILE, 'w', encoding='utf-8', newline='') as f:
                    pass
                log('[full] 上游名单为空，探活过滤直接跳过')
        
        # ★ 核心修复：只作为通行证读取，绝不修改 upstream_file 指针
        full_alive_set = load_ip_set(FULL_ALIVE_FILE)

    ip_list = []
    current_offset = 0
    total_all_ips = 0
    all_upstream_ips_len = 0
    batch_end = 0
    f_offset = 0

    if current_phase == 'common':
        all_ranges = load_ip_ranges(INPUT_FILE)
        if not all_ranges:
            log('未读取到有效 IP 范围')
            sys.exit(1)

        # ★ 千万级防 OOM 流式切片
        total_all_ips = get_total_ips_count(all_ranges)
        
        cursor_state = load_json(CURSOR_FILE) or {'offset': 0}
        current_offset = cursor_state.get('offset', 0)
        
        if current_offset >= total_all_ips:
            log('游标 %d >= 总IP数 %d，全部扫描完毕。' % (current_offset, total_all_ips))
            if SHARD_INDEX == 0:
                with open(FINISHED_FLAG, 'w') as f:
                    f.write('yes')
            _skip_this_shard(STATE_FILE, output_filter_file, current_phase, 0)
            return

        batch_end = min(current_offset + BATCH_SIZE, total_all_ips)
        batch_ips = get_ips_slice(all_ranges, current_offset, batch_end)
        log('当前批次游标: %d ~ %d，本批次共 %d 个 IP' % (current_offset, batch_end, len(batch_ips)))

        total_in_batch = len(batch_ips)
        shard_size = (total_in_batch + SHARD_TOTAL - 1) // SHARD_TOTAL
        lo = SHARD_INDEX * shard_size
        hi = min(lo + shard_size, total_in_batch)
        ip_list = batch_ips[lo:hi]
        
    else:
        if upstream_file is not None and os.path.exists(upstream_file):
            # ★ 核心稳定性修复：使用 load_ip_list 保证切片顺序绝对稳定
            wanted = load_ip_list(upstream_file)
            if wanted:
                all_ranges = []
                if os.path.exists(INPUT_FILE):
                    all_ranges = load_ip_ranges(INPUT_FILE)
                
                all_upstream_ips = []
                for w in wanted:
                    try:
                        ip_int = int(ipaddress.IPv4Address(w))
                    except Exception:
                        continue
                    note = ''
                    for s, e, n in all_ranges:
                        if s <= ip_int <= e:
                            note = n
                            break
                    all_upstream_ips.append((ip_int, note))
                
                all_upstream_ips_len = len(all_upstream_ips)

                if current_phase == 'full':
                    fc_state = load_json(FULL_CURSOR_FILE) or {'offset': 0}
                    f_offset = fc_state.get('offset', 0)
                    
                    if f_offset >= all_upstream_ips_len:
                        log('[full] 本片所有 IP 的全端口已扫完 (游标 %d >= %d)。' % (f_offset, all_upstream_ips_len))
                        _skip_this_shard(STATE_FILE, output_filter_file, current_phase, len(PORTS))
                        return
                        
                    batch_end = min(f_offset + FULL_BATCH_SIZE, all_upstream_ips_len)
                    ip_list = all_upstream_ips[f_offset:batch_end]
                    log('[full] 从上游文件加载: 本片共 %d 个，当前游标 %d~%d，本次扫 %d 个 IP 的全端口' 
                        % (all_upstream_ips_len, f_offset, batch_end, len(ip_list)))
                else:
                    ip_list = all_upstream_ips
                    log('[%s] 从上游文件 %s 加载了 %d 个 IP' % (current_phase, upstream_file, len(ip_list)))
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
    if total_ips == 0:
        log('[%s] 无待扫 IP，跳过' % current_phase)
        _skip_this_shard(STATE_FILE, output_filter_file, current_phase, len(PORTS))
        return

    def ip_at_position(pos):
        return ip_list[pos]

    state = load_json(STATE_FILE)
    
    if state and state.get('completed'):
        is_same_batch = (state.get('total_ips') == total_ips 
                         and state.get('phase') == current_phase)
        if is_same_batch:
            if current_phase == 'full' and state.get('f_offset') == f_offset:
                log('=== 断点续跑：本分片在游标 %d 已跑完，直接跳过 ===' % f_offset)
                _skip_this_shard(STATE_FILE, output_filter_file, current_phase, len(PORTS))
                return
            elif current_phase == 'common' and state.get('c_offset') == current_offset:
                log('=== 断点续跑：本分片在全局游标 %d 已跑完，直接跳过 ===' % current_offset)
                _skip_this_shard(STATE_FILE, output_filter_file, current_phase, len(PORTS))
                return
            elif current_phase not in ('full', 'common'):
                log('=== 断点续跑：本分片已跑完，直接跳过 ===')
                _skip_this_shard(STATE_FILE, output_filter_file, current_phase, len(PORTS))
                return

    new_round = True
    if (state and not state.get('completed')
            and state.get('total_ips') == total_ips
            and state.get('phase') == current_phase):
        if current_phase == 'full':
            if state.get('f_offset') == f_offset:
                new_round = False
        elif current_phase == 'common':
            if state.get('c_offset') == current_offset:
                new_round = False
        else:
            new_round = False

    if new_round:
        state = {
            'position': 0, 'done': 0, 'total_ips': total_ips,
            'phase': current_phase, 'shard_index': SHARD_INDEX,
            'shard_total': SHARD_TOTAL,
            'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'completed': False, 'session': 1,
        }
        if current_phase == 'full':
            state['f_offset'] = f_offset
            state['all_upstream_ips_len'] = all_upstream_ips_len
        elif current_phase == 'common':
            state['c_offset'] = current_offset

        with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
            f.write('@ 代理扫描结果 [分片 %d/%d, 阶段 %s]'
                    % (SHARD_INDEX, SHARD_TOTAL, current_phase) + CRLF)
            f.write('@ 开始时间: %s' % state['started_at'] + CRLF)
            f.write('@ 验证: 读秀 https（单验证）' + CRLF)
            f.write('@' + '-' * 58 + CRLF)
        existing = set()
        
        if current_phase == 'common':
            log('=== 批次扫描 (全局游标 %d) [分片 %d/%d, phase=%s] ==='
                % (current_offset, SHARD_INDEX, SHARD_TOTAL, current_phase))
        elif current_phase == 'full':
            log('=== 批次扫描 (全端口游标 %d) [分片 %d/%d, phase=%s] ==='
                % (f_offset, SHARD_INDEX, SHARD_TOTAL, current_phase))
        else:
            log('=== 批次扫描 [分片 %d/%d, phase=%s] ==='
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
        log('=== 断点续跑 [分片 %d/%d, phase=%s, session %d] ==='
            % (SHARD_INDEX, SHARD_TOTAL, current_phase, state['session']))
        log('上次位置: %d / %d (%.1f%%)'
            % (state['position'], total_ips,
               state['position'] * 100.0 / total_ips if total_ips else 0))

    start_position = state['position']

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

    if current_phase == 'common' and current_offset == 0:
        history_alive_count = 0
        global_proxy_count = 0

    log('本片 IP 总数: %d' % total_ips)
    log('端口数: %d' % len(PORTS))
    if current_phase in ('common', 'revalidate'):
        log('  前 12 探针: %s' % PROBE_PORTS_12)
    
    if current_phase == 'common':
        log('本次起点: 本片 IP #%d (全局游标 #%d / 总 %d)' % (state['position'], current_offset, total_all_ips))
    elif current_phase == 'full':
        log('本次起点: 本片 IP #%d (来源: %s, 游标 %d/%d)' % (state['position'], upstream_file, f_offset, all_upstream_ips_len))
    else:
        log('本次起点: 本片 IP #%d (来源: %s)' % (state['position'], upstream_file))
        
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

    # ★ 彻底分离线程池
    port_pool = ThreadPoolExecutor(max_workers=TCP_WORKERS * PORT_WORKERS)
    verify_pool = ThreadPoolExecutor(max_workers=VERIFY_WORKERS)

    # ★ 异步任务池（只存任务元组，不直接发 Future）
    pending_verify_tasks = []
    pending_verify_lock = threading.Lock()

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
            ip_start_time = time.time()  # ★ 记录该 IP 开始时间

            if current_phase == 'full':
                # ★ 核心修复：如果该 IP 不在前置探活的存活名单里，直接秒过，不扣发包数
                if full_alive_set is not None and ip not in full_alive_set:
                    with found_lock:
                        processed_ips[0] += 1
                        real_done = start_position + processed_ips[0]
                        pct = real_done * 100.0 / total_ips if total_ips else 0
                        elapsed = time.time() - t0
                        log('[full] IP %s 不在存活名单中(死IP复活失败)，直接跳过 | 本片 %d/%d (%.2f%%) | %.0f s'
                            % (ip, real_done, total_ips, pct, elapsed))
                    continue

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
                        log('[full] IP %s 探活失败 (188端口全闭)，跳过全端口 | 本片 %d/%d (%.2f%%) | %.0f s'
                            % (ip, real_done, total_ips, pct, elapsed))
                    continue

            if current_phase == 'full':
                chunk_size = 5000
                for i in range(0, len(PORTS), chunk_size):
                    # ★ 动态时间熔断：如果单 IP 耗时超过 300 秒(5分钟)且没代理，直接放弃
                    if time.time() - ip_start_time > MAX_IP_TIME_FULL and ip_proxy_count == 0:
                        log('[!] [full] IP %s 耗时超过 %d s (5分钟) 仍无代理，判定为高防/假死黑洞，强制熔断放弃剩余端口！' % (ip, MAX_IP_TIME_FULL))
                        break

                    chunk_ports = PORTS[i:i+chunk_size]
                    chunk_futures = []
                    for port in chunk_ports:
                        all_done = True
                        for proto in PROTOCOLS:
                            if '%s:%d:%s' % (ip, port, proto) not in existing:
                                all_done = False
                                break
                        if all_done:
                            continue
                        chunk_futures.append((port, port_pool.submit(tcp_check, ip, port)))
                    
                    for port, fut in chunk_futures:
                        if stop_flag[0]: return
                        try:
                            is_open = fut.result(timeout=TCP_TIMEOUT + 2)
                        except TimeoutError:
                            is_open = False
                        except Exception:
                            is_open = False
                        
                        if is_open:
                            ip_has_open = True
                            ip_open_count += 1
                            # 提交给 verify_pool 验证
                            v_fut = verify_pool.submit(scan_port_full, ip, port)
                            try:
                                _, r_list = v_fut.result(timeout=MAX_TIME + 5)
                            except TimeoutError:
                                r_list = []
                            except Exception:
                                r_list = []
                            
                            if r_list:
                                ip_has_proxy = True
                                for item in r_list:
                                    ip_, port_, proto_ = item
                                    key = '%s:%d:%s' % (ip_, port_, proto_)
                                    with found_lock:
                                        if key in existing: continue
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
                            
                            if port_tasks[0] >= SHARD_MAX_REQUESTS and not stop_flag[0]:
                                log('[!] 单分片探活次数达到 %d，触发换 IP 熔断！' % SHARD_MAX_REQUESTS)
                                stop_flag[0] = True
                                return
                    if stop_flag[0]: return

            else:
                futures = []
                for port in PORTS:
                    all_done = True
                    for proto in PROTOCOLS:
                        if '%s:%d:%s' % (ip, port, proto) not in existing:
                            all_done = False
                            break
                    if all_done:
                        continue
                    if current_phase == 'proxy':
                        futures.append((port, port_pool.submit(scan_port_full, ip, port, False)))
                    else:
                        futures.append((port, port_pool.submit(scan_fn, ip, port)))

                for port, fut in futures:
                    if stop_flag[0]:
                        return
                    # ★ 动态时间熔断：common / revalidate 使用短超时，proxy 使用 40 秒
                    if current_phase == 'proxy':
                        wait_timeout = 40
                    else:
                        wait_timeout = TCP_TIMEOUT + 2
                        
                    if time.time() - ip_start_time > MAX_IP_TIME_COMMON:
                        log('[!] [%s] IP %s 耗时超过 %d s (1分钟) 仍无结果，强制熔断剩余端口！' % (current_phase, ip, MAX_IP_TIME_COMMON))
                        break
                    try:
                        is_open, r_list = fut.result(timeout=wait_timeout)
                    except TimeoutError:
                        is_open, r_list = False, []
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
                        
                        if port_tasks[0] >= SHARD_MAX_REQUESTS and not stop_flag[0]:
                            log('[!] 单分片探活次数达到 %d，触发换 IP 熔断！' % SHARD_MAX_REQUESTS)
                            stop_flag[0] = True
                            return
                    if short_circuit and ip_has_open:
                        break

            if current_phase == 'common' and ip_has_open:
                # ★ 彻底异步化：只收集任务，不等待结果
                with pending_verify_lock:
                    for port in PROXY_PORTS:
                        pending_verify_tasks.append((ip, port))

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
                ip_elapsed = time.time() - ip_start_time  # ★ 计算该 IP 自己的耗时
                if current_phase == 'full':
                    elapsed = time.time() - t0
                    speed = port_tasks[0] / elapsed if elapsed > 0 else 0
                    log('[full] IP #%d %s 扫完 | 本 IP 耗时 %.0f s | 端口开放 %d, 代理 %d | 本片 %d/%d (%.2f%%) | 累计代理 %d | %.1f task/s | %.0f s'
                        % (real_done, ip, ip_elapsed, ip_open_count, ip_proxy_count,
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
        
        # ★ 动态扩容收尾：主线程结束了，如果有遗留任务，拉起 400 并发光速清理（峰值 1200 个 curl）
        with pending_verify_lock:
            leftover_tasks = pending_verify_tasks[:]
            pending_verify_tasks.clear()

        if leftover_tasks:
            log('[!] 正在启动 400 并发光速收尾，共 %d 个代理验证任务...' % len(leftover_tasks))
            final_pool = ThreadPoolExecutor(max_workers=400)
            futs = []
            for ip, port in leftover_tasks:
                futs.append(final_pool.submit(scan_port_full, ip, port))
            
            for fut in as_completed(futs):
                try:
                    _, r_list2 = fut.result(timeout=MAX_TIME + 5)
                except (TimeoutError, Exception):
                    r_list2 = []

                if r_list2:
                    for item in r_list2:
                        ip_, port_, proto_ = item
                        key = '%s:%d:%s' % (ip_, port_, proto_)
                        with found_lock:
                            if key in existing:
                                continue
                            existing.add(key)
                            found_count[0] += 1
                            line_out = '%s:%d@%s' % (ip_, port_, proto_)
                            with open(OUTPUT_FILE, 'a', encoding='utf-8', newline='') as f:
                                f.write(line_out + CRLF)
                            log('[★] [common] 发现有效代理(收尾): ' + line_out)
            final_pool.shutdown(wait=False)

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

    if current_phase == 'full':
        state['all_upstream_ips_len'] = all_upstream_ips_len
        if state.get('completed'):
            fc_state = load_json(FULL_CURSOR_FILE) or {'offset': 0}
            fc_state['offset'] += len(ip_list)
            save_json(FULL_CURSOR_FILE, fc_state)
            
            if fc_state['offset'] >= all_upstream_ips_len:
                log('[full] 本片所有 IP 已全部扫描完毕 (游标 %d >= %d)。' % (fc_state['offset'], all_upstream_ips_len))
            else:
                log('[full] 本批次扫完，游标推进至 %d，还剩余 %d 个 IP 待下次接力扫描。' % (fc_state['offset'], all_upstream_ips_len - fc_state['offset']))
        else:
            log('[full] 触发熔断或中断，保留游标 %d 不变，下一轮无缝续扫剩余端口。' % f_offset)

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
