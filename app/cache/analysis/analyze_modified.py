#!/usr/bin/env python3
"""
Analyze the causes of modified records:
- For each modified record, find which response triggered it
- Determine the response source: trigger response or resolver path response
- Determine whether it comes from a parent zone (non-AA) or child zone (AA)
- Analyze the specific cause of TTL refresh
"""

import json
import glob
import os
from pathlib import Path
from collections import defaultdict

def parse_dns_flags(flags):
    """Parse DNS flags bits"""
    return {
        'QR': (flags >> 15) & 1,
        'AA': (flags >> 10) & 1,  # Authoritative Answer
        'AD': (flags >> 5) & 1,   # Authentic Data
        'TC': (flags >> 9) & 1,   # Truncated
        'RCODE': flags & 0xF
    }

def find_matching_response(record_name, record_rtype, responses_list):
    """Find a matching record in the response list"""
    for resp_info in responses_list:
        if resp_info['name'] == record_name and resp_info['type'] == record_rtype:
            return resp_info
    return None

def analyze_modified_records(data_dir, output_file):
    """Analyze the causes of all modified records"""

    files = glob.glob(os.path.join(data_dir, "analyze_*.json"))
    print(f"Found {len(files)} files to analyze...")

    results = {
        "summary": {
            "total_files": len(files),
            "total_modified_records": 0,
            "by_resolver": {},
            "by_source": {
                "trigger_response": 0,      # From trigger response
                "resolver_path_aa": 0,      # From resolver path (AA response)
                "resolver_path_non_aa": 0,  # From resolver path (non-AA response)
                "implicit_refresh": 0,      # Implicit refresh (not in any response)
                "unknown": 0
            },
            "by_rtype": {},
            "ttl_analysis": {
                "ttl_increased": 0,          # TTL increased (refresh)
                "ttl_decreased": 0,          # TTL decreased
                "ttl_unchanged": 0,          # TTL unchanged (possibly other field changes)
                "reset_to_original": 0,      # Reset to original TTL
                "avg_ttl_change": 0          # Average TTL change
            }
        },
        "details": []
    }

    total_ttl_change = 0

    for file_path in files:
        try:
            filename = Path(file_path).stem
            iteration_id = filename.split('_')[1] if '_' in filename else filename

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content: continue
                data = json.loads(content)

            # Get cache and resolver data
            for key in data:
                if not key.startswith("cache:"):
                    continue

                resolver_name = key.replace("cache:", "")
                cache_diff = data[key].get('diff', {})
                modified_records = cache_diff.get('modified', [])

                if not modified_records:
                    continue

                # Get trigger response
                trigger = cache_diff.get('trigger', {})
                trigger_responses = []

                flags = trigger.get('flags', 0)
                trigger_aa = (flags >> 10) & 1

                for section_name in ['answers', 'authorities', 'additionals']:
                    for rec in trigger.get(section_name, []):
                        if rec.get('type') == 'OPT':
                            continue
                        trigger_responses.append({
                            'name': rec.get('name'),
                            'type': rec.get('type'),
                            'ttl': rec.get('ttl'),
                            'aa': trigger_aa,
                            'section': section_name,
                            'source': 'trigger'
                        })

                # Get resolver path responses
                resolver_key = f"resolver:{resolver_name}"
                transaction = data.get(resolver_key, {}).get('transaction', {})
                path = transaction.get('analyzed_path', {})
                steps = path.get('steps', [])

                path_responses = []
                for step_idx, step in enumerate(steps):
                    resp = step.get('response', {})
                    if not resp:
                        continue

                    resp_flags = resp.get('flags', 0)
                    resp_aa = (resp_flags >> 10) & 1

                    for section_name in ['answers', 'authorities', 'additionals']:
                        for rec in resp.get(section_name, []):
                            if rec.get('type') == 'OPT':
                                continue
                            path_responses.append({
                                'name': rec.get('name'),
                                'type': rec.get('type'),
                                'ttl': rec.get('ttl'),
                                'aa': resp_aa,
                                'section': section_name,
                                'source': 'resolver_path',
                                'step_idx': step_idx,
                                'server_ip': step.get('server_ip', '')
                            })

                # Initialize statistics for resolver
                if resolver_name not in results["summary"]["by_resolver"]:
                    results["summary"]["by_resolver"][resolver_name] = {
                        "total_modified": 0,
                        "from_trigger": 0,
                        "from_resolver_aa": 0,
                        "from_resolver_non_aa": 0,
                        "implicit_refresh": 0,
                        "by_rtype": {}
                    }

                res_stats = results["summary"]["by_resolver"][resolver_name]

                # Analyze each modified record
                for mod in modified_records:
                    results["summary"]["total_modified_records"] += 1
                    res_stats["total_modified"] += 1

                    old = mod.get('old', {})
                    new = mod.get('new', {})

                    record_name = old.get('name', '')
                    record_rtype = old.get('rtype', 'UNKNOWN')
                    old_ttl = old.get('ttl', 0)
                    new_ttl = new.get('ttl', 0)
                    original_ttl = old.get('original_ttl', new.get('original_ttl', 0))

                    # Count rtype
                    if record_rtype not in results["summary"]["by_rtype"]:
                        results["summary"]["by_rtype"][record_rtype] = 0
                    results["summary"]["by_rtype"][record_rtype] += 1

                    if record_rtype not in res_stats["by_rtype"]:
                        res_stats["by_rtype"][record_rtype] = 0
                    res_stats["by_rtype"][record_rtype] += 1

                    # TTL change analysis
                    ttl_change = new_ttl - old_ttl
                    total_ttl_change += ttl_change

                    if new_ttl > old_ttl:
                        results["summary"]["ttl_analysis"]["ttl_increased"] += 1
                    elif new_ttl < old_ttl:
                        results["summary"]["ttl_analysis"]["ttl_decreased"] += 1
                    else:
                        results["summary"]["ttl_analysis"]["ttl_unchanged"] += 1

                    if new_ttl == original_ttl and original_ttl > 0:
                        results["summary"]["ttl_analysis"]["reset_to_original"] += 1

                    # Find trigger source
                    source_type = "unknown"
                    source_info = {}

                    # 1. Check trigger first
                    match = find_matching_response(record_name, record_rtype, trigger_responses)
                    if match:
                        source_type = "trigger_response"
                        results["summary"]["by_source"]["trigger_response"] += 1
                        res_stats["from_trigger"] += 1
                        source_info = {
                            "aa": match['aa'],
                            "section": match['section'],
                            "response_ttl": match['ttl']
                        }
                    else:
                        # 2. Check resolver path
                        match = find_matching_response(record_name, record_rtype, path_responses)
                        if match:
                            if match['aa'] == 1:
                                source_type = "resolver_path_aa"
                                results["summary"]["by_source"]["resolver_path_aa"] += 1
                                res_stats["from_resolver_aa"] += 1
                            else:
                                source_type = "resolver_path_non_aa"
                                results["summary"]["by_source"]["resolver_path_non_aa"] += 1
                                res_stats["from_resolver_non_aa"] += 1

                            source_info = {
                                "aa": match['aa'],
                                "section": match['section'],
                                "step_idx": match['step_idx'],
                                "server_ip": match['server_ip'],
                                "response_ttl": match['ttl']
                            }
                        else:
                            # 3. Implicit refresh
                            source_type = "implicit_refresh"
                            results["summary"]["by_source"]["implicit_refresh"] += 1
                            res_stats["implicit_refresh"] += 1

                    # Record details
                    detail = {
                        "iteration": iteration_id,
                        "resolver": resolver_name,
                        "record": {
                            "name": record_name,
                            "rtype": record_rtype,
                            "old_ttl": old_ttl,
                            "new_ttl": new_ttl,
                            "original_ttl": original_ttl,
                            "ttl_change": ttl_change
                        },
                        "source_type": source_type,
                        "source_info": source_info
                    }

                    results["details"].append(detail)

        except Exception as e:
            print(f"Error processing {file_path}: {e}")

    # Calculate average TTL change
    if results["summary"]["total_modified_records"] > 0:
        results["summary"]["ttl_analysis"]["avg_ttl_change"] = total_ttl_change / results["summary"]["total_modified_records"]

    # Save results
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print("Modified Records Analysis Complete")
    print(f"{'='*60}")
    print(f"\nTotal modified records: {results['summary']['total_modified_records']}")

    print(f"\n{'='*60}")
    print("By Source:")
    print(f"{'='*60}")
    print(f"  From trigger response: {results['summary']['by_source']['trigger_response']}")
    print(f"  From resolver path (AA): {results['summary']['by_source']['resolver_path_aa']}")
    print(f"  From resolver path (non-AA): {results['summary']['by_source']['resolver_path_non_aa']}")
    print(f"  Implicit refresh (prefetch/background): {results['summary']['by_source']['implicit_refresh']}")

    print(f"\n{'='*60}")
    print("By Resolver:")
    print(f"{'='*60}")
    for resolver, stats in results['summary']['by_resolver'].items():
        print(f"\n  {resolver}:")
        print(f"    Total: {stats['total_modified']}")
        print(f"    From trigger: {stats['from_trigger']}")
        print(f"    From resolver (AA): {stats['from_resolver_aa']}")
        print(f"    From resolver (non-AA): {stats['from_resolver_non_aa']}")
        print(f"    Implicit refresh: {stats['implicit_refresh']}")

    print(f"\n{'='*60}")
    print("TTL Analysis:")
    print(f"{'='*60}")
    ttl_stats = results['summary']['ttl_analysis']
    print(f"  TTL increased (refresh): {ttl_stats['ttl_increased']}")
    print(f"  TTL decreased: {ttl_stats['ttl_decreased']}")
    print(f"  TTL unchanged: {ttl_stats['ttl_unchanged']}")
    print(f"  Reset to original TTL: {ttl_stats['reset_to_original']}")
    print(f"  Average TTL change: {ttl_stats['avg_ttl_change']:.2f}")

    print(f"\n{'='*60}")
    print("By RTYPE:")
    print(f"{'='*60}")
    for rtype, count in sorted(results['summary']['by_rtype'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {rtype}: {count}")

    print(f"\n{'='*60}")
    print(f"Results saved to: {output_file}")
    print(f"{'='*60}")

    return results


if __name__ == "__main__":
    DATA_DIR = "./fuzzer_output/analyze"
    OUTPUT_FILE = "./modified_analysis.json"

    analyze_modified_records(DATA_DIR, OUTPUT_FILE)