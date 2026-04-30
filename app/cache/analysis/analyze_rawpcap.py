#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, Tuple, List

try:
    from dnsbuilder import Zone
except ImportError:
    class Zone:
        def __init__(self, name):
            self.name = name.lower().strip('.') if name and name != '.' else '.'
        def __str__(self):
            return f"{self.name}." if self.name != '.' else "."

def normalize_zone(name: str) -> Zone:
    if not name: return Zone(".")
    return Zone(name)

def normalize_ns_rdata(rdata: str, owner_name: str = None) -> str:
    rdata = rdata.strip()
    if not rdata: return ""
    if rdata.endswith('.'): return str(normalize_zone(rdata))
    labels = rdata.split('.')
    if len(labels) >= 3: return str(normalize_zone(rdata))
    if owner_name:
        owner = normalize_zone(owner_name)
        if len(owner.parts) >= 1:
            full_name = f"{rdata}.{owner.label}."
            return str(normalize_zone(full_name))
    return rdata.lower()

SIMPLE_MATCH_TYPES = {'NSEC3', 'NSEC', 'DS', 'DNSKEY', 'CDNSKEY', 'CDSSKEY', 'RRSIG', 'SOA', 'TXT'}
TIME_WINDOW = 10.0
TTL_TOLERANCE = 10  # TTL allowed error range (seconds)

def normalize_rdata_for_comparison(rdata_str: str) -> str:
    return ' '.join(str(rdata_str).split())

def parse_fuzzer_item(item: Dict) -> Tuple[str, str, str, int]:
    name = str(normalize_zone(item.get('name', '')))
    rtype = str(item.get('rtype', item.get('type', ''))).upper()
    ttl = int(item.get('ttl', 0))
    rdata = item.get('rdata', '')
    if isinstance(rdata, dict):
        if 'address' in rdata: rdata_str = str(rdata['address'])
        elif 'nsname' in rdata: rdata_str = normalize_ns_rdata(str(rdata['nsname']), item.get('name', ''))
        elif 'cname' in rdata: rdata_str = str(normalize_zone(str(rdata['cname'])))
        elif 'ptrdname' in rdata: rdata_str = str(normalize_zone(str(rdata['ptrdname'])))
        else: rdata_str = str(sorted(rdata.items()))
    else:
        rdata_str = str(rdata)
        if rtype == 'NS': rdata_str = normalize_ns_rdata(rdata_str, item.get('name', ''))
        elif rtype in ('CNAME', 'PTR', 'DNAME'): rdata_str = str(normalize_zone(rdata_str))
    return name, rtype, normalize_rdata_for_comparison(rdata_str), ttl

def parse_tshark_rr(rr_key_str: str, rr_dict: Dict) -> Dict:
    name = str(normalize_zone(rr_dict.get('dns.resp.name', '')))
    rtype = ''
    if 'type ' in rr_key_str:
        parts = rr_key_str.split('type ')
        if len(parts) > 1:
            rtype = parts[1].split(',')[0].strip()

    if not rtype:
        type_code = str(rr_dict.get('dns.resp.type', ''))
        tmap = {'1': 'A', '2': 'NS', '5': 'CNAME', '6': 'SOA', '12': 'PTR', '15': 'MX', '16': 'TXT', '28': 'AAAA', '39': 'DNAME', '41': 'OPT', '43': 'DS', '46': 'RRSIG', '47': 'NSEC', '48': 'DNSKEY', '50': 'NSEC3'}
        rtype = tmap.get(type_code, type_code)

    rdata = ''
    if rtype == 'A': rdata = rr_dict.get('dns.a', '')
    elif rtype == 'AAAA': rdata = rr_dict.get('dns.aaaa', '')
    elif rtype == 'NS': rdata = normalize_ns_rdata(rr_dict.get('dns.ns', ''), name)
    elif rtype == 'CNAME': rdata = str(normalize_zone(rr_dict.get('dns.cname', '')))

    # Extract TTL
    ttl = 0
    ttl_str = rr_dict.get('dns.resp.ttl', '')
    if ttl_str:
        try: ttl = int(ttl_str)
        except ValueError: ttl = 0

    return {'name': name, 'rtype': rtype, 'rdata': normalize_rdata_for_comparison(rdata), 'ttl': ttl}

def load_tshark_index(tshark_dir: Path) -> Dict:
    print(f"\nLoading PCAP (tshark) data to build ground truth index...")
    index = defaultdict(list)
    for p in tshark_dir.glob('*.json'):
        with open(p, 'r') as f:
            try: packets = json.load(f)
            except Exception: continue
        for pkt in packets:
            layers = pkt.get('_source', {}).get('layers', {})
            dns = layers.get('dns')
            if not dns: continue
            ts_str = layers.get('frame', {}).get('frame.time_epoch', '0')
            try: timestamp = float(ts_str)
            except ValueError:
                from datetime import datetime
                try:
                    time_part, fraction_tz = ts_str.split('.')
                    fraction = fraction_tz.replace('Z', '').replace('+', '')[:6]
                    timestamp = datetime.fromisoformat(f"{time_part}.{fraction}+00:00").timestamp()
                except Exception: timestamp = 0.0
            dst_ip = layers.get('ip', layers.get('ipv6', {})).get('ip.dst', layers.get('ip', layers.get('ipv6', {})).get('ipv6.dst', ''))

            def process_section(section_names, section_type):
                for sname in section_names:
                    for raw_key, rr_dict in dns.get(sname, {}).items():
                        if not isinstance(rr_dict, dict) or 'dns.resp.name' not in rr_dict: continue
                        parsed = parse_tshark_rr(raw_key, rr_dict)
                        index[(parsed['name'], parsed['rtype'])].append({
                            'rdata': parsed['rdata'], 'timestamp': timestamp, 'section': section_type,
                            'resolver_ip': dst_ip, 'ttl': parsed['ttl']
                        })
            process_section(['Answers'], 'an')
            process_section(['Authoritative nameservers', 'Authoritative_nameservers'], 'aa')
            process_section(['Additional records', 'Additional_records'], 'ad')

    for k in index: index[k].sort(key=lambda x: x['timestamp'])
    print(f"-> Built {len(index)} record group indexes.")
    return index

# Core search function
def find_source_section(tshark_index, resolver_ip, c_name, c_rtype, c_rdata, target_ts, cache_ttl=0):
    """
    Find which DNS section a cache record originated from.

    TTL matching logic:
    - If the cache record has TTL = cache_ttl at target_ts
    - And the record came from a pcap response at timestamp with original TTL = pcap_ttl
    - Then theoretically: cache_ttl ≈ pcap_ttl - (target_ts - timestamp)
    - i.e.: expected_ttl = pcap_ttl - time_elapsed
    """
    candidates = tshark_index.get((c_name, c_rtype), [])
    valid_matches = []

    for c in candidates:
        if c['resolver_ip'] != resolver_ip:
            continue

        time_diff = abs(c['timestamp'] - target_ts)

        # Time window check
        if c_rtype not in SIMPLE_MATCH_TYPES and time_diff > 300.0:
            continue

        # TTL matching check
        pcap_ttl = c.get('ttl', 0)
        ttl_match_score = 0

        if cache_ttl > 0 and pcap_ttl > 0:
            # Calculate expected TTL (accounting for decay)
            time_elapsed = target_ts - c['timestamp']
            if time_elapsed >= 0:
                expected_ttl = pcap_ttl - time_elapsed
                ttl_diff = abs(cache_ttl - expected_ttl)

                # TTL error within tolerance range gets bonus score
                if ttl_diff <= TTL_TOLERANCE:
                    ttl_match_score = 100 - ttl_diff  # Closer match = higher score
                elif expected_ttl >= 0 and cache_ttl > 0:
                    # Allow some deviation, but reduce score
                    ttl_match_score = max(0, 50 - ttl_diff)

        # rdata matching check
        rdata_match = (c_rtype in SIMPLE_MATCH_TYPES) or (c['rdata'].lower() == c_rdata.lower())

        # Combined scoring: smaller time difference is better, TTL match bonus, rdata match required
        score = -time_diff + ttl_match_score
        valid_matches.append({
            'time_diff': time_diff,
            'ttl_match_score': ttl_match_score,
            'rdata_match': rdata_match,
            'score': score,
            'candidate': c
        })

    if not valid_matches:
        return 'unknown'

    # Prefer rdata match with best TTL match
    rdata_matched = [m for m in valid_matches if m['rdata_match']]
    if rdata_matched:
        # Among rdata matches, sort by combined score
        rdata_matched.sort(key=lambda x: (-x['ttl_match_score'], x['time_diff']))
        best = rdata_matched[0]
    else:
        # Without rdata match, select by smallest time difference
        valid_matches.sort(key=lambda x: x['time_diff'])
        best = valid_matches[0]

    return best['candidate']['section']

def main():
    if len(sys.argv) < 3:
        print("Usage: python analyze_pcap_cache.py <fuzzer_json_directory> <tshark_json_directory> [-v]")
        sys.exit(1)

    fuzzer_dir, tshark_dir = Path(sys.argv[1]), Path(sys.argv[2])
    verbose = '-v' in sys.argv

    resolver_ip_map = {'bind': '10.10.66.3', 'bind-new': '10.10.66.4', 'unbound': '10.10.66.5', 'unbound-new': '10.10.66.6'}
    ip_to_resolver = {v: k for k, v in resolver_ip_map.items()}

    tshark_index = load_tshark_index(tshark_dir)
    fuzzer_files = [f for f in fuzzer_dir.glob('analyze_*.json') if not f.name.endswith('.analysis.json')]

    stats = defaultdict(lambda: {'total': 0, 'an': 0, 'aa': 0, 'ad': 0, 'unknown': 0, 'transitions': defaultdict(int)})
    transition_details = defaultdict(list)  # Record detailed info for each transition
    reverse_stats = defaultdict(lambda: {'an': {'total': 0, 'cached': 0}, 'aa': {'total': 0, 'cached': 0}, 'ad': {'total': 0, 'cached': 0}})
    fuzzer_additions = defaultdict(lambda: defaultdict(list))

    print(f"\nAnalyzing {len(fuzzer_files)} Fuzzer cache states...")

    for fuzzer_file in fuzzer_files:
        with open(fuzzer_file, 'r') as f: data = json.load(f)

        for key in data:
            if not key.startswith('cache:'): continue
            resolver_name, resolver_ip = key[6:], resolver_ip_map.get(key[6:])
            if not resolver_ip or data[key].get('status') != 'success': continue

            diff = data[key].get('diff', {})
            trigger_ts = diff.get('trigger', {}).get('timestamp', 0)

            # Process Added records
            for item in [i for i in diff.get('added', []) if not i.get('is_neg', False)]:
                stats[resolver_name]['total'] += 1
                c_name, c_rtype, c_rdata, c_ttl = parse_fuzzer_item(item)

                # Register for Reverse Lookup
                fuzzer_additions[resolver_ip][(c_name, c_rtype, c_rdata)].append(trigger_ts)

                section = find_source_section(tshark_index, resolver_ip, c_name, c_rtype, c_rdata, trigger_ts, c_ttl)
                stats[resolver_name][section] += 1

            # Process Modified records (core update logic)
            for item in diff.get('modified', []):
                old_item = item.get('old', {})
                new_item = item.get('new', {})
                if old_item.get('is_neg', False): continue

                old_ts = old_item.get('timestamp', 0)
                old_ttl = int(old_item.get('ttl', 0))
                new_ts = new_item.get('timestamp', 0)
                new_ttl = int(new_item.get('ttl', 0))
                c_name, c_rtype, c_rdata, _ = parse_fuzzer_item(new_item)

                # Trace the source of the old record (using old record's TTL)
                old_sec = find_source_section(tshark_index, resolver_ip, c_name, c_rtype, c_rdata, old_ts, old_ttl)
                # Trace the source of the new record that refreshed it (using new record's TTL)
                new_sec = find_source_section(tshark_index, resolver_ip, c_name, c_rtype, c_rdata, trigger_ts, new_ttl)

                # Record state transition: "old_new"
                transition_key = f"{old_sec}_{new_sec}"
                stats[resolver_name]['transitions'][transition_key] += 1

                # Record detailed info
                transition_details[resolver_name].append({
                    'transition': transition_key,
                    'name': c_name,
                    'rtype': c_rtype,
                    'rdata': c_rdata,
                    'old_timestamp': old_ts,
                    'old_ttl': old_ttl,
                    'new_timestamp': new_ts,
                    'new_ttl': new_ttl,
                    'trigger_timestamp': trigger_ts,
                    'old_section': old_sec,
                    'new_section': new_sec,
                    'source_file': fuzzer_file.name
                })

    # Extract reverse statistics
    for rr_key, pcap_records in tshark_index.items():
        for rec in pcap_records:
            res_ip, section, pcap_ts = rec['resolver_ip'], rec['section'], rec['timestamp']
            res_name = ip_to_resolver.get(res_ip)
            if not res_name: continue

            reverse_stats[res_name][section]['total'] += 1
            full_key = (rr_key[0], rr_key[1], normalize_rdata_for_comparison(rec['rdata']))

            is_cached = any(abs(pcap_ts - ts) <= TIME_WINDOW for ts in fuzzer_additions[res_ip].get(full_key, []))
            if is_cached: reverse_stats[res_name][section]['cached'] += 1

    # Convert transitions to standard dict for JSON saving
    for r in stats: stats[r]['transitions'] = dict(stats[r]['transitions'])

    output_data = {
        "forward_analysis_cache_to_pcap": dict(stats),
        "reverse_analysis_pcap_to_cache": dict(reverse_stats),
        "transition_details": dict(transition_details)
    }
    with open("analysis_results.json", 'w') as f:
        json.dump(output_data, f, indent=4, ensure_ascii=False)
    print("Analysis complete! Output analysis_results.json with Transitions data.")

if __name__ == '__main__':
    main()