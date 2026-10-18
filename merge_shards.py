# -*- coding: utf-8 -*-
"""
合并 8 个分片结果，判断阶段推进 / 触发下一轮 / 清理
五阶段：verify_existing → common → revalidate → proxy → full

关键逻辑：
  - verify_existing：**替换** working_proxies.txt（只留仍有效的）
  - 其他阶段：**累积**（旧 + 新，去重）
  - common 内嵌代理验证 → 输出 proxy_ips_shardN.txt（供 revalidate 用）
  - revalidate 只对 proxy_ips_shardN.txt 里的 IP 二次探活
  - proxy 找到 ≥1 条记录 → 跳过 full（节约原则）
  - 一轮完整结束 → phase.json 重置为 verify_existing（若 working_proxies.txt 非空）或 common
  - ★ 全空检测：分片文件全不存在 = 分片 job 全失败 → 不清理、不推进、trigger=yes
  - ★ 存活 IP 段统计：一轮完整结束时生成 alive_ip_ranges.txt
  - ★ 存活 IP 明细：一轮完整结束时生成 alive_ips.txt
"""

import os
import sys
import json
import time
import glob
import re
import ipaddress

SHARD_TOTAL = 8
PHASE_FILE = 'phase.json'
OUTPUT_FILE = 'working_proxies.txt'
ALIVE_IPS_FILE = 'alive_ips.txt'
ALIVE_IP_RANGES_FILE = 'alive_ip_ranges.txt'
CRLF = '\r\n'


def log(msg):
    print(msg, flush=True)


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def save_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def read_shard_results(idx):
    path = 'working_proxies_shard%d.txt' % idx
    if not os.path.exists(path):
        return []
    lines = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if not line or line.startswith('@') or line.startswith('#'):
                continue
            lines.append(line)
    return lines


def read_file_lines(path):
    if not os.path.exists(path):
        return []
    lines = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if not line or line.startswith('@') or line.startswith('#'):
                continue
            lines.append(line)
    return lines


def proxy_key(line):
    if '@' not in line:
        return line
    parts = line.split('@')
    if len(parts) >= 2:
        return '%s@%s' % (parts[0], parts[1])
    return line


def count_file_lines(path):
    return len(read_file_lines(path))


def cleanup_shard_files():
    patterns = [
        'progress_shard*.json',
        'open_ips_shard*.txt',
        'proxy_ips_shard*.txt',
        'open_ips_revalidated_shard*.txt',
        'proxy_missing_shard*.txt',
        'working_proxies_shard*.txt',
    ]
    removed = 0
    for pat in patterns:
        for path in glob.glob(pat):
            try:
                os.remove(path)
                removed += 1
            except Exception as e:
                log('[!] 删除 %s 失败: %s' % (path, e))
    log('已清理 %d 个分片文件' % removed)


def write_output(lines):
    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
        f.write('@ 代理扫描结果' + CRLF)
        f.write('@ 格式: ip:port@protocol@归属地' + CRLF)
        f.write('@ 生成时间: %s' % time.strftime('%Y-%m-%d %H:%M:%S') + CRLF)
        f.write('@ 总数: %d' % len(lines) + CRLF)
        f.write('@' + '-' * 58 + CRLF)
        for line in lines:
            f.write(line + CRLF)


def set_trigger(value):
    runner_temp = os.environ.get('RUNNER_TEMP', '/tmp')
    with open(os.path.join(runner_temp, 'trigger.flag'), 'w') as f:
        f.write(value)


def _parse_ip_range(line):
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('@'):
        return None
    
    # ★ 统一先提取 | 后面的归属地
    note = ''
    if '|' in line:
        parts = line.split('|', 1)
        line = parts[0].strip()
        note = parts[1].strip()

    for tok in line.split():
        if '/' in tok:
            try:
                net = ipaddress.ip_network(tok, strict=False)
                if net.version != 4:
                    continue
                return int(net.network_address), int(net.broadcast_address), note
            except Exception:
                pass

    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})', line)
    if m:
        a, b = m.group(1), m.group(2)
        try:
            sa = int(ipaddress.IPv4Address(a))
            sb = int(ipaddress.IPv4Address(b))
            return min(sa, sb), max(sa, sb), note
        except Exception:
            pass
            
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
    if m:
        try:
            a = int(ipaddress.IPv4Address(m.group(1)))
            return a, a, note
        except Exception:
            pass
    return None


def build_alive_ip_ranges():
    alive_ints = set()
    for i in range(SHARD_TOTAL):
        path = 'open_ips_shard%d.txt' % i
        if not os.path.exists(path):
            continue
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alive_ints.add(int(ipaddress.IPv4Address(line)))
                except Exception:
                    pass

    ranges = []
    if os.path.exists('ip_list.txt'):
        with open('ip_list.txt', 'r', encoding='utf-8-sig', errors='ignore') as f:
            for line in f:
                r = _parse_ip_range(line)
                if r:
                    ranges.append(r)

    # ★ 生成 alive_ips.txt（明细）
    ip_to_note = {}
    for ip_int in alive_ints:
        for s, e, note in ranges:
            if s <= ip_int <= e:
                ip_to_note[ip_int] = note
                break

    with open(ALIVE_IPS_FILE, 'w', encoding='utf-8', newline='') as f:
        f.write('@ 存活 IP 明细' + CRLF)
        f.write('@ 生成时间: %s' % time.strftime('%Y-%m-%d %H:%M:%S') + CRLF)
        f.write('@ 存活 IP 总数: %d' % len(alive_ints) + CRLF)
        f.write('@ 格式: IP|归属地' + CRLF)
        f.write('@' + '-' * 58 + CRLF)
        for ip_int in sorted(alive_ints):
            ip_str = str(ipaddress.IPv4Address(ip_int))
            note = ip_to_note.get(ip_int, '')
            if note:
                f.write('%s|%s' % (ip_str, note) + CRLF)
            else:
                f.write(ip_str + CRLF)
    log('已生成 %s: %d 个存活 IP' % (ALIVE_IPS_FILE, len(alive_ints)))

    # 生成存活 IP 段统计
    stats = [0] * len(ranges)
    for ip_int in alive_ints:
        for idx, (s, e, note) in enumerate(ranges):
            if s <= ip_int <= e:
                stats[idx] += 1
                break

    items = []
    for idx in range(len(ranges)):
        if stats[idx] > 0:
            s, e, note = ranges[idx]
            items.append((stats[idx], s, e, note))
    items.sort(key=lambda x: -x[0])

    with open(ALIVE_IP_RANGES_FILE, 'w', encoding='utf-8', newline='') as f:
        f.write('@ 存活 IP 段统计' + CRLF)
        f.write('@ 生成时间: %s' % time.strftime('%Y-%m-%d %H:%M:%S') + CRLF)
        f.write('@ 存活 IP 总数: %d' % len(alive_ints) + CRLF)
        f.write('@ 有存活的段数: %d / %d' % (len(items), len(ranges)) + CRLF)
        f.write('@ 排序: 按存活数从高到低' + CRLF)
        f.write('@ 格式: 存活数<TAB>起始IP - 结束IP<TAB>备注' + CRLF)
        f.write('@' + '-' * 58 + CRLF)
        for cnt, s, e, note in items:
            f.write('%d\t%s - %s\t%s' % (
                cnt,
                str(ipaddress.IPv4Address(s)),
                str(ipaddress.IPv4Address(e)),
                note,
            ) + CRLF)

    log('已生成 %s: %d 个段有存活 IP，共 %d 存活 IP'
        % (ALIVE_IP_RANGES_FILE, len(items), len(alive_ints)))


def handle_verify_existing(phase_state):
    all_done = True
    missing_shards = []
    for i in range(SHARD_TOTAL):
        st = load_json('progress_shard%d.json' % i)
        if not st or not st.get('completed') or st.get('phase') != 'verify_existing':
            all_done = False
            missing_shards.append(i)

    log('阶段: verify_existing')
    log('全部分片完成: %s' % all_done)
    if not all_done:
        log('未完成分片: %s' % missing_shards)

    shard0_lines = read_shard_results(0)
    log('分片 0 验证结果: %d 个仍然有效' % len(shard0_lines))

    write_output(shard0_lines)
    log('已替换 working_proxies.txt: %d 条' % len(shard0_lines))

    if not all_done:
        log('有分片未完成（被截断），自动触发下一轮续跑')
        set_trigger('yes')
        return

    if len(shard0_lines) > 0:
        log('verify_existing 完成，%d 个代理仍有效 → 结束（保留列表，等手动触发）'
            % len(shard0_lines))
        cleanup_shard_files()
        save_json(PHASE_FILE, {
            'current': 'verify_existing',
            'common_completed': False,
            'revalidate_completed': False,
            'proxy_completed': False,
            'full_completed': False,
        })
        log('phase.json 已重置为 verify_existing（下次触发仍先验证）')
        set_trigger('no')
    else:
        log('verify_existing 完成，0 个代理仍有效 → 清空并自动进 common')
        cleanup_shard_files()
        save_json(PHASE_FILE, {
            'current': 'common',
            'common_completed': False,
            'revalidate_completed': False,
            'proxy_completed': False,
            'full_completed': False,
        })
        log('phase.json 已重置为 common（自动触发下一轮）')
        set_trigger('yes')


def main():
    phase_state = load_json(PHASE_FILE) or {
        'current': 'common',
        'common_completed': False,
        'revalidate_completed': False,
        'proxy_completed': False,
        'full_completed': False,
    }
    current_phase = phase_state.get('current', 'common')

    if current_phase == 'verify_existing':
        handle_verify_existing(phase_state)
        return

    has_any_shard_file = any(
        os.path.exists('working_proxies_shard%d.txt' % i) or
        os.path.exists('progress_shard%d.json' % i) or
        os.path.exists('open_ips_shard%d.txt' % i) or
        os.path.exists('proxy_ips_shard%d.txt' % i) or
        os.path.exists('open_ips_revalidated_shard%d.txt' % i) or
        os.path.exists('proxy_missing_shard%d.txt' % i)
        for i in range(SHARD_TOTAL)
    )
    if not has_any_shard_file:
        log('=' * 60)
        log('⚠️ 所有分片文件都不存在——分片 job 可能全部失败')
        log('⚠️ 保留 phase.json 状态不动（current=%s）' % current_phase)
        log('⚠️ 触发下一轮重跑')
        log('=' * 60)
        set_trigger('yes')
        return

    all_done = True
    missing_shards = []
    for i in range(SHARD_TOTAL):
        st = load_json('progress_shard%d.json' % i)
        if not st or not st.get('completed') or st.get('phase') != current_phase:
            all_done = False
            missing_shards.append(i)

    log('阶段: %s' % current_phase)
    log('全部分片完成: %s' % all_done)
    if not all_done:
        log('未完成分片: %s' % missing_shards)

    total_open = sum(count_file_lines('open_ips_shard%d.txt' % i)
                     for i in range(SHARD_TOTAL))
    total_proxy_ips = sum(count_file_lines('proxy_ips_shard%d.txt' % i)
                          for i in range(SHARD_TOTAL))
    total_rev = sum(count_file_lines('open_ips_revalidated_shard%d.txt' % i)
                    for i in range(SHARD_TOTAL))
    total_missing = sum(count_file_lines('proxy_missing_shard%d.txt' % i)
                        for i in range(SHARD_TOTAL))
    log('存活 IP 总数: %d' % total_open)
    log('有代理的 IP 总数: %d' % total_proxy_ips)
    log('重验存活 IP 总数: %d' % total_rev)
    log('待深扫 IP 总数: %d' % total_missing)

    old_lines = read_file_lines(OUTPUT_FILE)
    new_lines = []
    for i in range(SHARD_TOTAL):
        new_lines.extend(read_shard_results(i))

    seen = set()
    merged = []
    for line in new_lines:
        k = proxy_key(line)
        if k in seen:
            continue
        seen.add(k)
        merged.append(line)
    for line in old_lines:
        k = proxy_key(line)
        if k in seen:
            continue
        seen.add(k)
        merged.append(line)

    log('本轮分片结果: %d 条 | 旧文件: %d 条 | 合并去重后: %d 条'
        % (len(new_lines), len(old_lines), len(merged)))

    write_output(merged)

    trigger = 'no'
    should_cleanup = False

    if not all_done:
        log('有分片未完成（被截断），自动触发下一轮续跑')
        trigger = 'yes'
    else:
        if current_phase == 'common':
            if total_open == 0:
                log('common 完成，0 存活 IP → 结束（IP 全死）')
                phase_state['common_completed'] = True
                phase_state['revalidate_completed'] = True
                phase_state['proxy_completed'] = True
                phase_state['full_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'no'
                should_cleanup = True
            elif total_proxy_ips == 0:
                log('common 完成，0 个有代理的 IP → 结束（无代理可深验）')
                phase_state['common_completed'] = True
                phase_state['revalidate_completed'] = True
                phase_state['proxy_completed'] = True
                phase_state['full_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'no'
                should_cleanup = True
            else:
                log('common 完成，%d 存活 IP / %d 有代理的 IP → 切 revalidate（只验有代理的 IP）'
                    % (total_open, total_proxy_ips))
                phase_state['current'] = 'revalidate'
                phase_state['common_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'yes'

        elif current_phase == 'revalidate':
            if total_rev == 0:
                log('revalidate 完成，0 重验存活 IP → 结束')
                phase_state['revalidate_completed'] = True
                phase_state['proxy_completed'] = True
                phase_state['full_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'no'
                should_cleanup = True
            else:
                log('revalidate 完成，%d 个重验存活 IP → 切 proxy' % total_rev)
                phase_state['current'] = 'proxy'
                phase_state['revalidate_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'yes'

        elif current_phase == 'proxy':
            if len(new_lines) >= 1:
                log('proxy 完成，本轮找到 %d 个代理 → 结束（节约原则，跳过 full）'
                    % len(new_lines))
                phase_state['proxy_completed'] = True
                phase_state['full_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'no'
                should_cleanup = True
            else:
                log('proxy 完成，0 条代理 → 切 full（深扫剩余 %d 个 IP）'
                    % total_missing)
                phase_state['current'] = 'full'
                phase_state['proxy_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'yes'

        elif current_phase == 'full':
            log('full 全部完成 → 结束')
            phase_state['full_completed'] = True
            save_json(PHASE_FILE, phase_state)
            trigger = 'no'
            should_cleanup = True

    if should_cleanup:
        log('=' * 60)
        log('一轮完整结束，生成存活 IP 明细及段统计 + 清理分片文件...')

        try:
            build_alive_ip_ranges()
        except Exception as e:
            log('[!] 生成存活 IP 文件失败: %s' % e)

        cleanup_shard_files()

        current_count = count_file_lines(OUTPUT_FILE)
        if current_count > 0:
            next_phase = 'verify_existing'
            log('working_proxies.txt 有 %d 个代理，下一轮先做 verify_existing'
                % current_count)
        else:
            next_phase = 'common'
            log('working_proxies.txt 为空，下一轮从头开始')

        save_json(PHASE_FILE, {
            'current': next_phase,
            'common_completed': False,
            'revalidate_completed': False,
            'proxy_completed': False,
            'full_completed': False,
        })
        log('phase.json 已重置为 %s' % next_phase)

    set_trigger(trigger)
    log('trigger = %s' % trigger)


if __name__ == '__main__':
    main()
