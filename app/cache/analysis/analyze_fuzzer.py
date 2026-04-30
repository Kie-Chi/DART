#!/usr/bin/env python3
"""
Analyze fuzzer output JSON data, computing the proportion of cache change items
derived from each DNS section (an/aa/ad) during resolver resolution.

Analysis logic:
1. For each cache item, find a match across the resolver resolution path
2. Compute the proportion of cache items sourced from answers(an), authorities(aa), additionals(ad)
3. Use the dnsbuilder.Zone class to normalize domain name formats uniformly

Usage:
    python analyze_fuzzer.py <json_file_path>
    python analyze_fuzzer.py analyze_1775811269.json [-v]
"""

import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from dnsbuilder import Zone
import base64
from datetime import datetime, timezone


def normalize_zone(name: str) -> Zone:
    """
    Normalize a domain name using the Zone class.
    Supports FQDN, label, abbreviated, and other formats.
    """
    if not name:
        return Zone(".")
    return Zone(name)


def normalize_ns_rdata(rdata: str, owner_name: str = None) -> str:
    """
    Normalize NS record rdata.

    NS rdata in cache can appear in three formats:
    1. "a.ns" - Abbreviated form (relative domain name), needs completion based on owner_name
    2. "b.example.com." - FQDN form (ending with .)
    3. "c.example.com" - Full domain name without trailing dot

    Args:
        rdata: NS record rdata
        owner_name: Owner domain name of the NS record (used to complete abbreviated forms)

    Returns:
        Unified FQDN format for matching
    """
    rdata = rdata.strip()
    if not rdata:
        return ""

    # If it ends with ., it's FQDN — normalize directly
    if rdata.endswith('.'):
        return str(normalize_zone(rdata))

    # Count the number of labels
    labels = rdata.split('.')
    label_count = len(labels)

    # If label count >= 3, treat as a full domain name (no trailing dot) — normalize directly
    # e.g. "a.ns.apple.com" has 4 labels
    if label_count >= 3:
        return str(normalize_zone(rdata))

    # Label count < 3, this is an abbreviated form
    # Needs completion based on owner_name
    if owner_name:
        owner = normalize_zone(owner_name)
        if len(owner.parts) >= 1:
            # Complete the domain name
            full_name = f"{rdata}.{owner.label}."
            return str(normalize_zone(full_name))

    # Unable to complete, keep as-is
    return rdata.lower()


def format_rrsig_rdata(rdata: Dict) -> str:
    """
    Convert RRSIG rdata dict to standard text format.
    Format: <type_covered> <algorithm> <labels> <original_ttl> <signature_expiration> <signature_inception> <key_tag> <signer_name> <signature>

    Note: Timestamps are converted to YYYYMMDDHHMMSS format, signatures to base64 format.
    """
    # type_covered can be a number or a string
    type_covered = rdata.get('type_covered', '')
    if isinstance(type_covered, int):
        # Convert type code to type name
        type_map = {1: 'A', 2: 'NS', 5: 'CNAME', 28: 'AAAA', 43: 'DS', 47: 'NSEC', 50: 'NSEC3'}
        type_covered = type_map.get(type_covered, str(type_covered))

    algorithm = rdata.get('algorithm', '')
    labels = rdata.get('labels', '')
    original_ttl = rdata.get('original_ttl', '')

    # Process timestamps: Convert Unix timestamps to YYYYMMDDHHMMSS format
    sig_exp = rdata.get('signature_expiration', '')
    sig_inc = rdata.get('signature_inception', '')

    if isinstance(sig_exp, (int, float)):
        dt = datetime.fromtimestamp(sig_exp, tz=timezone.utc)
        sig_exp = dt.strftime('%Y%m%d%H%M%S')

    if isinstance(sig_inc, (int, float)):
        dt = datetime.fromtimestamp(sig_inc, tz=timezone.utc)
        sig_inc = dt.strftime('%Y%m%d%H%M%S')

    key_tag = rdata.get('key_tag', '')
    signer_name = str(normalize_zone(str(rdata.get('signer_name', ''))))

    # Process signature: convert hex to base64
    signature = rdata.get('signature', '')
    if signature and all(c in '0123456789abcdefABCDEF' for c in signature):
        # Hex format, convert to base64
        try:
            sig_bytes = bytes.fromhex(signature)
            signature = base64.b64encode(sig_bytes).decode('ascii')
        except ValueError:
            pass  # Keep as-is

    return f"{type_covered} {algorithm} {labels} {original_ttl} {sig_exp} {sig_inc} {key_tag} {signer_name} {signature}"


def format_nsec3_rdata(rdata: Dict) -> str:
    """
    Convert NSEC3 rdata dict to standard text format.
    Format: <hash_algorithm> <flags> <iterations> <salt> <next_hashed_owner> <type_bitmap>
    """
    hash_algo = rdata.get('hash_algorithm', 0)
    flags = rdata.get('flags', 0)
    iterations = rdata.get('iterations', 0)
    salt = rdata.get('salt', '') or '-'
    next_hashed = rdata.get('next_hashed_owner', '') or ''
    type_bitmap = rdata.get('type_bitmap', '')

    return f"{hash_algo} {flags} {iterations} {salt} {next_hashed} {type_bitmap}".strip()


def format_nsec_rdata(rdata: Dict) -> str:
    """
    Convert NSEC rdata dict to standard text format.
    Format: <next_name> <type_bitmap>
    """
    next_name = str(normalize_zone(str(rdata.get('next_domain_name', rdata.get('next_name', '')))))
    type_bitmap = rdata.get('type_bitmap', '')
    return f"{next_name} {type_bitmap}".strip()


def format_ds_rdata(rdata: Dict) -> str:
    """
    Convert DS rdata dict to standard text format.
    Format: <key_tag> <algorithm> <digest_type> <digest>
    """
    key_tag = rdata.get('key_tag', '')
    algorithm = rdata.get('algorithm', '')
    digest_type = rdata.get('digest_type', '')
    digest = rdata.get('digest', '')
    return f"{key_tag} {algorithm} {digest_type} {digest}"


def normalize_rdata_for_comparison(rdata_str: str) -> str:
    """
    Normalize rdata string for comparison.
    Main processing: remove extra whitespace, unify base64 format, etc.
    """
    # Remove whitespace in base64 signatures (common formatting in DNS records)
    parts = rdata_str.split()
    if len(parts) > 8:
        # Likely RRSIG or similar records with long signatures — merge signature part
        # Format: type algorithm labels ttl exp inc key_tag signer signature...
        # The signature portion may be split by whitespace
        first_parts = parts[:8]  # First 8 fields
        signature = ''.join(parts[8:])  # Merge signature portion
        return ' '.join(first_parts + [signature])
    return rdata_str


# Record types that do not require exact rdata matching (DNSSEC-related)
# These types only need to match name and type
SIMPLE_MATCH_TYPES = {'NSEC3', 'NSEC', 'DS', 'DNSKEY', 'CDNSKEY', 'CDSSKEY'}


def extract_rr_key(rr: Dict) -> Tuple[str, str, str]:
    """
    Extract unique identification key (name, type, rdata) from an RR record.
    Used to compare cache items with records in responses.
    Uses the Zone class for domain-name-type rdata.
    """
    # Normalize name using Zone class
    name = str(normalize_zone(rr.get('name', '')))
    rtype = str(rr.get('rtype', rr.get('type', ''))).upper()

    # rdata can be a string or dict
    rdata = rr.get('rdata', '')
    if isinstance(rdata, dict):
        # Process different types of rdata
        if 'address' in rdata:
            # A/AAAA records: use IP address directly
            rdata_str = str(rdata['address'])
        elif 'nsname' in rdata:
            # NS records: handle abbreviated and FQDN formats, pass name for completion
            rdata_str = normalize_ns_rdata(str(rdata['nsname']), rr.get('name', ''))
        elif 'cname' in rdata:
            # CNAME records: normalize domain name using Zone class
            rdata_str = str(normalize_zone(str(rdata['cname'])))
        elif 'ptrdname' in rdata:
            # PTR records: normalize domain name using Zone class
            rdata_str = str(normalize_zone(str(rdata['ptrdname'])))
        elif 'type_covered' in rdata:
            # RRSIG records
            rdata_str = format_rrsig_rdata(rdata)
        elif 'hash_algorithm' in rdata or 'iterations' in rdata:
            # NSEC3 records
            rdata_str = format_nsec3_rdata(rdata)
        elif 'next_domain_name' in rdata or 'next_name' in rdata:
            # NSEC records
            rdata_str = format_nsec_rdata(rdata)
        elif 'key_tag' in rdata and 'digest' in rdata:
            # DS records
            rdata_str = format_ds_rdata(rdata)
        elif 'mname' in rdata or 'rname' in rdata:
            # SOA records: multiple domain name fields, convert to string representation
            rdata_str = str(sorted(rdata.items()))
        else:
            # Other types: convert to string
            rdata_str = str(sorted(rdata.items()))
    else:
        # rdata is a string
        rdata_str = str(rdata)
        # For NS records, handle abbreviated and FQDN formats, pass name for completion
        if rtype == 'NS':
            rdata_str = normalize_ns_rdata(rdata_str, rr.get('name', ''))
        elif rtype in ('CNAME', 'PTR', 'DNAME'):
            # Other domain-name-type records, normalize using Zone class
            rdata_str = str(normalize_zone(rdata_str))

    # Normalize rdata string for comparison
    rdata_str = normalize_rdata_for_comparison(rdata_str)

    # For NSEC3 and similar DNSSEC types, simplify matching (match only name and type, ignore rdata)
    if rtype in SIMPLE_MATCH_TYPES:
        rdata_str = '*'  # Use wildcard to indicate any rdata matches

    return (name, rtype, rdata_str)


def build_resolver_rr_index(resolver_data: Dict) -> Tuple[Dict, Dict]:
    """
    Build an index of all RR records from the resolver resolution path.
    Returns: (index, section_counts)
        - index: {rr_key: [{'step_idx': int, 'section': str, 'rr': dict}, ...]}
        - section_counts: {'an': int, 'aa': int, 'ad': int} total record count per section
    """
    index = defaultdict(list)
    section_counts = {'an': 0, 'aa': 0, 'ad': 0}

    transaction = resolver_data.get('transaction', {})
    analyzed_path = transaction.get('analyzed_path', {})
    steps = analyzed_path.get('steps', [])

    for step_idx, step in enumerate(steps):
        response = step.get('response')
        if not response:
            continue

        # Index answers
        for rr in response.get('answers', []):
            key = extract_rr_key(rr)
            index[key].append({
                'step_idx': step_idx,
                'section': 'an',
                'rr': rr,
                'server_ip': step.get('server_ip', ''),
            })
            section_counts['an'] += 1

        # Index authorities
        for rr in response.get('authorities', []):
            key = extract_rr_key(rr)
            index[key].append({
                'step_idx': step_idx,
                'section': 'aa',
                'rr': rr,
                'server_ip': step.get('server_ip', ''),
            })
            section_counts['aa'] += 1

        # Index additionals (skip OPT)
        for rr in response.get('additionals', []):
            if rr.get('type', rr.get('rtype', '')) == 'OPT':
                continue
            key = extract_rr_key(rr)
            index[key].append({
                'step_idx': step_idx,
                'section': 'ad',
                'rr': rr,
                'server_ip': step.get('server_ip', ''),
            })
            section_counts['ad'] += 1

    return index, section_counts


def analyze_resolver_pair(data: Dict, resolver_name: str) -> Dict:
    """
    Analyze a single resolver pair (cache + resolver).
    Correlate via trigger's qname/qtype with resolver's query_name/query_type.
    """
    cache_key = f'cache:{resolver_name}'
    resolver_key = f'resolver:{resolver_name}'

    result = {
        'resolver_name': resolver_name,
        'cache_status': None,
        'resolver_status': None,
        'trigger_query': None,  # Record trigger query info
        'matched': False,  # Whether successfully matched
        'added_stats': {'total': 0, 'an': 0, 'aa': 0, 'ad': 0, 'unknown': 0, 'details': []},
        'modified_stats': {'total': 0, 'an': 0, 'aa': 0, 'ad': 0, 'unknown': 0, 'details': []},
        'removed_stats': {'total': 0, 'details': []},
    }

    # Check cache data
    cache_data = data.get(cache_key, {})
    result['cache_status'] = cache_data.get('status', 'not_found')

    if cache_data.get('status') != 'success':
        return result

    diff = cache_data.get('diff', {})

    # Get trigger info
    trigger = diff.get('trigger', {})
    trigger_qname = trigger.get('qname', '')
    trigger_qtype = trigger.get('qtype', '')
    result['trigger_query'] = {'qname': trigger_qname, 'qtype': trigger_qtype}

    # Check resolver data
    resolver_data = data.get(resolver_key, {})
    result['resolver_status'] = resolver_data.get('status', 'not_found')

    # Build resolver RR index
    rr_index = {}
    if resolver_data.get('status') == 'success':
        transaction = resolver_data.get('transaction', {})
        resolver_qname = transaction.get('query_name', '')
        resolver_qtype = transaction.get('query_type', '')

        # Check if matched (qname and qtype must be the same)
        if trigger_qname.lower() == resolver_qname.lower() and trigger_qtype == resolver_qtype:
            result['matched'] = True
            rr_index, section_counts = build_resolver_rr_index(resolver_data)

            result['resolver_info'] = {
                'query_name': resolver_qname,
                'query_type': resolver_qtype,
                'duration': transaction.get('duration', 0),
                'rcode': transaction.get('rcode', ''),
                'answer_count': transaction.get('answer_count', 0),
                'tot_resolv_qs': transaction.get('analyzed_path', {}).get('stats', {}).get('tot_resolv_qs', 0),
                'servers': transaction.get('analyzed_path', {}).get('stats', {}).get('servers', {}),
            }

            # Count RR records per section in resolver
            result['resolver_rr_stats'] = {
                'an_total': section_counts['an'],
                'aa_total': section_counts['aa'],
                'ad_total': section_counts['ad'],
                'unique_rr': len(rr_index),
            }
        else:
            # Not matched, record the reason
            result['match_info'] = {
                'trigger_query': f'{trigger_qname} ({trigger_qtype})',
                'resolver_query': f'{resolver_qname} ({resolver_qtype})',
                'reason': 'Query mismatch'
            }

    # Analyze added items (exclude negative cache)
    for item in diff.get('added', []):
        # Skip negative cache
        if item.get('is_neg', False):
            continue

        result['added_stats']['total'] += 1
        cache_key_rr = extract_rr_key(item)

        # Look up in resolver index
        matches = rr_index.get(cache_key_rr, [])

        if matches:
            # Found a match, count occurrences per section
            sections = [m['section'] for m in matches]
            # Choose the first occurrence's section as the source
            first_match = matches[0]
            result['added_stats'][first_match['section']] += 1

            result['added_stats']['details'].append({
                'name': item.get('name', ''),
                'rtype': item.get('rtype', ''),
                'rdata': item.get('rdata', ''),
                'source': first_match['section'],
                'all_sections': sections,
                'step_idx': first_match['step_idx'],
                'server_ip': first_match['server_ip'],
            })
        else:
            result['added_stats']['unknown'] += 1
            result['added_stats']['details'].append({
                'name': item.get('name', ''),
                'rtype': item.get('rtype', ''),
                'rdata': item.get('rdata', ''),
                'source': None,
                'all_sections': [],
            })

    # Analyze modified items (exclude negative cache)
    for item in diff.get('modified', []):
        # Skip negative cache
        if item.get('is_neg', False):
            continue

        result['modified_stats']['total'] += 1
        cache_key_rr = extract_rr_key(item)

        matches = rr_index.get(cache_key_rr, [])

        if matches:
            first_match = matches[0]
            result['modified_stats'][first_match['section']] += 1

            result['modified_stats']['details'].append({
                'name': item.get('name', ''),
                'rtype': item.get('rtype', ''),
                'rdata': item.get('rdata', ''),
                'source': first_match['section'],
                'step_idx': first_match['step_idx'],
                'server_ip': first_match['server_ip'],
            })
        else:
            result['modified_stats']['unknown'] += 1
            result['modified_stats']['details'].append({
                'name': item.get('name', ''),
                'rtype': item.get('rtype', ''),
                'rdata': item.get('rdata', ''),
                'source': None,
            })

    # Count removed items
    for item in diff.get('removed', []):
        result['removed_stats']['total'] += 1
        result['removed_stats']['details'].append({
            'name': item.get('name', ''),
            'rtype': item.get('rtype', ''),
            'rdata': item.get('rdata', ''),
        })

    # Trigger statistics
    trigger = diff.get('trigger', {})
    result['trigger_stats'] = {
        'answers': len(trigger.get('answers', [])),
        'authorities': len(trigger.get('authorities', [])),
        'additionals': len([r for r in trigger.get('additionals', []) if r.get('type') != 'OPT']),
        'qname': trigger.get('qname', ''),
        'qtype': trigger.get('qtype', ''),
    }

    return result


def print_analysis_report(results: List[Dict], verbose: bool = False):
    """
    Print analysis report
    """
    print("=" * 80)
    print("FUZZER Analysis Report - Cache Change Source Statistics")
    print("Source definition: an=answers, aa=authorities, ad=additionals")
    print("=" * 80)

    for r in results:
        print(f"\n{'─' * 40}")
        print(f"Resolver: {r['resolver_name']}")
        print(f"{'─' * 40}")

        print(f"Cache status: {r['cache_status']}")
        print(f"Resolver status: {r['resolver_status']}")

        # Show trigger query info
        if r.get('trigger_query'):
            tq = r['trigger_query']
            print(f"Trigger query: {tq['qname']} ({tq['qtype']})")

        # Show match status
        if not r.get('matched', True):
            print(f"Match status: Unmatched")
            if r.get('match_info'):
                mi = r['match_info']
                print(f"  Trigger: {mi['trigger_query']}")
                print(f"  Resolver: {mi['resolver_query']}")
                print(f"  Reason: {mi['reason']}")
        else:
            print(f"Match status: Matched")

        if r.get('resolver_info'):
            info = r['resolver_info']
            print(f"\nResolver info:")
            print(f"  Query: {info['query_name']} ({info['query_type']})")
            print(f"  Response: {info['rcode']}, {info['answer_count']} answers")
            print(f"  Resolution duration: {info['duration']:.3f}s")
            print(f"  Total queries: {info['tot_resolv_qs']}")
            print(f"  Servers: {info['servers']}")

        if r.get('resolver_rr_stats'):
            rrs = r['resolver_rr_stats']
            print(f"\nResolver response RR statistics:")
            print(f"  RR in Answers: {rrs['an_total']}")
            print(f"  RR in Authorities: {rrs['aa_total']}")
            print(f"  RR in Additionals: {rrs['ad_total']}")
            print(f"  Unique RR count: {rrs['unique_rr']}")

        if r.get('trigger_stats'):
            ts = r['trigger_stats']
            print(f"\nTrigger message:")
            print(f"  Query: {ts['qname']} ({ts['qtype']})")
            print(f"  Answers: {ts['answers']}, Authorities: {ts['authorities']}, Additionals: {ts['additionals']}")

        # Added statistics
        stats = r['added_stats']
        print(f"\nAdded statistics (total {stats['total']} items):")
        if stats['total'] > 0:
            total = stats['total']
            an_pct = stats['an']/total*100 if total > 0 else 0
            aa_pct = stats['aa']/total*100 if total > 0 else 0
            ad_pct = stats['ad']/total*100 if total > 0 else 0
            unk_pct = stats['unknown']/total*100 if total > 0 else 0

            print(f"  Source an(answers):    {stats['an']:3d} ({an_pct:5.1f}%)")
            print(f"  Source aa(authorities): {stats['aa']:3d} ({aa_pct:5.1f}%)")
            print(f"  Source ad(additionals): {stats['ad']:3d} ({ad_pct:5.1f}%)")
            print(f"  Unmatched:              {stats['unknown']:3d} ({unk_pct:5.1f}%)")

            if verbose and stats['details']:
                print(f"\n  Added details:")
                for d in stats['details']:
                    src = d['source'] or '?'
                    extra = f" (step={d.get('step_idx')}, server={d.get('server_ip')})" if d['source'] else ""
                    all_sec = f" [{','.join(d.get('all_sections', []))}]" if d.get('all_sections') else ""
                    print(f"    [{src}] {d['name']} {d['rtype']} = {d['rdata']}{extra}{all_sec}")

        # Modified statistics
        stats = r['modified_stats']
        print(f"\nModified statistics (total {stats['total']} items):")
        if stats['total'] > 0:
            total = stats['total']
            an_pct = stats['an']/total*100 if total > 0 else 0
            aa_pct = stats['aa']/total*100 if total > 0 else 0
            ad_pct = stats['ad']/total*100 if total > 0 else 0
            unk_pct = stats['unknown']/total*100 if total > 0 else 0

            print(f"  Source an: {stats['an']} ({an_pct:.1f}%)")
            print(f"  Source aa: {stats['aa']} ({aa_pct:.1f}%)")
            print(f"  Source ad: {stats['ad']} ({ad_pct:.1f}%)")
            print(f"  Unmatched: {stats['unknown']} ({unk_pct:.1f}%)")

            if verbose and stats['details']:
                print(f"\n  Modified details:")
                for d in stats['details']:
                    src = d['source'] or '?'
                    print(f"    [{src}] {d['name']} {d['rtype']} = {d['rdata']}")

        # Removed statistics
        stats = r['removed_stats']
        print(f"\nRemoved statistics (total {stats['total']} items):")
        if verbose and stats['details']:
            print(f"\n  Removed details:")
            for d in stats['details']:
                print(f"    {d['name']} {d['rtype']} = {d['rdata']}")

    print("\n" + "=" * 80)
    print("Summary Statistics")
    print("=" * 80)

    # Summary by resolver name
    for r in results:
        resolver_name = r['resolver_name']
        print(f"\n{resolver_name}:")
        if r['added_stats']['total'] > 0:
            total = r['added_stats']['total']
            print(f"  Added total: {total}")
            print(f"    an: {r['added_stats']['an']} ({r['added_stats']['an']/total*100:.1f}%)")
            print(f"    aa: {r['added_stats']['aa']} ({r['added_stats']['aa']/total*100:.1f}%)")
            print(f"    ad: {r['added_stats']['ad']} ({r['added_stats']['ad']/total*100:.1f}%)")
            print(f"    ?:  {r['added_stats']['unknown']} ({r['added_stats']['unknown']/total*100:.1f}%)")
        else:
            print(f"  Added total: 0")

        if r['modified_stats']['total'] > 0:
            total = r['modified_stats']['total']
            print(f"  Modified total: {total}")
            print(f"    an: {r['modified_stats']['an']}, aa: {r['modified_stats']['aa']}, ad: {r['modified_stats']['ad']}, ?: {r['modified_stats']['unknown']}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_fuzzer.py <json_file_or_directory> [-v|--verbose]")
        print("  -v, --verbose: Show detailed information")
        print("\nIf input is a directory, all *.json files in that directory will be analyzed")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    verbose = '-v' in sys.argv or '--verbose' in sys.argv

    # Determine the list of files to analyze
    if input_path.is_dir():
        json_files = sorted(input_path.glob('analyze_*.json'))
        # Exclude previously generated analysis files
        json_files = [f for f in json_files if not f.name.endswith('.analysis.json')]
        if not json_files:
            print(f"Error: No analyze_*.json files found in directory {input_path}")
            sys.exit(1)
        print(f"Found {len(json_files)} analyze_*.json files in directory {input_path}")
    elif input_path.is_file():
        json_files = [input_path]
    else:
        print(f"Error: Path does not exist {input_path}")
        sys.exit(1)

    # First pass: collect all cache and resolver data
    print("\nFirst pass: collecting all cache and resolver data...")
    all_cache_data = []  # [{file, resolver_name, trigger_timestamp, trigger_qname, trigger_qtype, cache_items}]
    all_resolver_data = []  # [{file, resolver_name, query_name, query_type, rr_index, resolver_info}]

    for json_path in json_files:
        with open(json_path, 'r') as f:
            data = json.load(f)

        # Collect cache data
        for key in data:
            if key.startswith('cache:'):
                resolver_name = key[6:]  # 'cache:' is 6 chars
                cache_entry = data[key]
                if cache_entry.get('status') == 'success':
                    diff = cache_entry.get('diff', {})
                    trigger = diff.get('trigger', {})
                    trigger_timestamp = trigger.get('timestamp', 0)
                    trigger_qname = trigger.get('qname', '').lower()
                    trigger_qtype = trigger.get('qtype', '')

                    # Collect cache items (exclude negative cache)
                    cache_items = {
                        'added': [item for item in diff.get('added', []) if not item.get('is_neg', False)],
                        'modified': [item for item in diff.get('modified', []) if not item.get('is_neg', False)],
                        'removed': diff.get('removed', []),
                    }

                    all_cache_data.append({
                        'file': json_path.name,
                        'resolver_name': resolver_name,
                        'trigger_timestamp': trigger_timestamp,
                        'trigger_qname': trigger_qname,
                        'trigger_qtype': trigger_qtype,
                        'cache_items': cache_items,
                    })

        # Collect resolver data
        for key in data:
            if key.startswith('resolver:'):
                resolver_name = key[9:]  # 'resolver:' is 9 chars
                resolver_entry = data[key]
                if resolver_entry.get('status') == 'success':
                    transaction = resolver_entry.get('transaction', {})
                    query_name = transaction.get('query_name', '').lower()
                    query_type = transaction.get('query_type', '')

                    # Get resolver resolution step timestamps (timestamp of the first query)
                    steps = transaction.get('analyzed_path', {}).get('steps', [])
                    resolver_timestamp = 0
                    if steps:
                        first_step = steps[0]
                        resolver_timestamp = first_step.get('query', {}).get('timestamp', 0)

                    # Build RR index
                    rr_index, section_counts = build_resolver_rr_index(resolver_entry)

                    resolver_info = {
                        'query_name': query_name,
                        'query_type': query_type,
                        'duration': transaction.get('duration', 0),
                        'rcode': transaction.get('rcode', ''),
                        'answer_count': transaction.get('answer_count', 0),
                        'tot_resolv_qs': transaction.get('analyzed_path', {}).get('stats', {}).get('tot_resolv_qs', 0),
                        'servers': transaction.get('analyzed_path', {}).get('stats', {}).get('servers', {}),
                    }

                    rr_stats = {
                        'an_total': section_counts['an'],
                        'aa_total': section_counts['aa'],
                        'ad_total': section_counts['ad'],
                        'unique_rr': len(rr_index),
                    }

                    all_resolver_data.append({
                        'file': json_path.name,
                        'resolver_name': resolver_name,
                        'resolver_timestamp': resolver_timestamp,
                        'query_name': query_name,
                        'query_type': query_type,
                        'rr_index': rr_index,
                        'section_counts': section_counts,
                        'resolver_info': resolver_info,
                        'rr_stats': rr_stats,
                    })

    print(f"Collected {len(all_cache_data)} cache entries, {len(all_resolver_data)} resolver entries")

    # Second pass: match each cache to its corresponding resolver (considering time window)
    print("\nSecond pass: matching each cache to its corresponding resolver (considering all responses within the time window)...")
    matched_results = []  # Match results for each cache entry

    # Group resolver data by resolver_name for fast lookup
    resolver_by_name = defaultdict(list)
    for r in all_resolver_data:
        resolver_by_name[r['resolver_name']].append(r)

    # Sort resolver data by timestamp per resolver
    for resolver_name in resolver_by_name:
        resolver_by_name[resolver_name].sort(key=lambda x: x['resolver_timestamp'])

    # Time window size: how many resolver entries to take before and after
    TIME_WINDOW_SIZE = 5

    for cache in all_cache_data:
        resolver_name = cache['resolver_name']
        trigger_qname = cache['trigger_qname']
        trigger_qtype = cache['trigger_qtype']
        trigger_timestamp = cache['trigger_timestamp']

        # Search within the same resolver's data for a match
        candidates = resolver_by_name[resolver_name]

        # Find the main resolver corresponding to the trigger (qname and qtype both match)
        main_resolver = None
        main_resolver_idx = -1
        for idx, r in enumerate(candidates):
            if r['query_name'] == trigger_qname and r['query_type'] == trigger_qtype:
                # Find the closest timestamp
                if main_resolver is None:
                    main_resolver = r
                    main_resolver_idx = idx
                else:
                    if abs(r['resolver_timestamp'] - trigger_timestamp) < abs(main_resolver['resolver_timestamp'] - trigger_timestamp):
                        main_resolver = r
                        main_resolver_idx = idx

        # Collect all resolvers within the time window (TIME_WINDOW_SIZE before and after)
        window_resolvers = []
        window_start = max(0, main_resolver_idx - TIME_WINDOW_SIZE)
        window_end = min(len(candidates), main_resolver_idx + TIME_WINDOW_SIZE + 1) if main_resolver_idx >= 0 else 0

        if main_resolver_idx >= 0:
            for idx in range(window_start, window_end):
                window_resolvers.append(candidates[idx])

        # Merge RR indexes from all resolvers within the time window
        merged_rr_index = defaultdict(list)
        resolver_file_set = set()
        # Count total section records from all resolvers within the time window (for reverse statistics)
        window_section_counts = {'an': 0, 'aa': 0, 'ad': 0}

        for r in window_resolvers:
            resolver_file_set.add(r['file'])
            # Accumulate section counts
            for section in ['an', 'aa', 'ad']:
                window_section_counts[section] += r.get('section_counts', {}).get(section, 0)

            for key, matches in r['rr_index'].items():
                for m in matches:
                    # Add resolver_file info to each match
                    merged_rr_index[key].append({
                        'step_idx': m['step_idx'],
                        'section': m['section'],
                        'rr': m['rr'],
                        'server_ip': m['server_ip'],
                        'resolver_file': r['file'],
                        'resolver_query': f"{r['query_name']} ({r['query_type']})",
                    })

        # Analysis result
        result = {
            'cache_file': cache['file'],
            'resolver_name': resolver_name,
            'trigger_query': {'qname': trigger_qname, 'qtype': trigger_qtype},
            'trigger_timestamp': trigger_timestamp,
            'matched': main_resolver is not None,
            'resolver_file': main_resolver['file'] if main_resolver else None,
            'resolver_timestamp': main_resolver['resolver_timestamp'] if main_resolver else None,
            'window_resolvers_count': len(window_resolvers),
            'window_resolver_files': list(resolver_file_set),
            'window_section_counts': window_section_counts,
            'added_stats': {'total': 0, 'an': 0, 'aa': 0, 'ad': 0, 'unknown': 0, 'sources': []},
            'modified_stats': {'total': 0, 'an': 0, 'aa': 0, 'ad': 0, 'unknown': 0, 'sources': []},
            'removed_stats': {'total': 0},
            # Reverse statistics: how many records from each section entered cache
            'section_cache_stats': {'an': {'total': 0, 'cached': 0}, 'aa': {'total': 0, 'cached': 0}, 'ad': {'total': 0, 'cached': 0}},
        }

        if main_resolver:
            result['resolver_info'] = main_resolver['resolver_info']
            result['rr_stats'] = main_resolver['rr_stats']

            # Initialize reverse statistics
            section_cached_keys = {'an': set(), 'aa': set(), 'ad': set()}

            # Analyze added items (using merged RR index)
            for item in cache['cache_items']['added']:
                result['added_stats']['total'] += 1
                cache_key_rr = extract_rr_key(item)
                matches = merged_rr_index.get(cache_key_rr, [])

                if matches:
                    first_match = matches[0]
                    result['added_stats'][first_match['section']] += 1
                    # Record that this section's key has been cached
                    section_cached_keys[first_match['section']].add(cache_key_rr)
                    result['added_stats']['sources'].append({
                        'name': item.get('name', ''),
                        'rtype': item.get('rtype', ''),
                        'source_section': first_match['section'],
                        'source_resolver_file': first_match['resolver_file'],
                        'source_resolver_query': first_match['resolver_query'],
                    })
                else:
                    result['added_stats']['unknown'] += 1
                    result['added_stats']['sources'].append({
                        'name': item.get('name', ''),
                        'rtype': item.get('rtype', ''),
                        'source_section': None,
                        'source_resolver_file': None,
                    })

            # Analyze modified items
            for item in cache['cache_items']['modified']:
                result['modified_stats']['total'] += 1
                cache_key_rr = extract_rr_key(item)
                matches = merged_rr_index.get(cache_key_rr, [])

                if matches:
                    first_match = matches[0]
                    result['modified_stats'][first_match['section']] += 1
                    # modified also counts as cached (just an update)
                    section_cached_keys[first_match['section']].add(cache_key_rr)
                    result['modified_stats']['sources'].append({
                        'name': item.get('name', ''),
                        'rtype': item.get('rtype', ''),
                        'source_section': first_match['section'],
                        'source_resolver_file': first_match['resolver_file'],
                    })
                else:
                    result['modified_stats']['unknown'] += 1
                    result['modified_stats']['sources'].append({
                        'name': item.get('name', ''),
                        'rtype': item.get('rtype', ''),
                        'source_section': None,
                        'source_resolver_file': None,
                    })

            # Count removed items
            result['removed_stats']['total'] = len(cache['cache_items']['removed'])

            # Calculate reverse statistics: how many records from each section entered cache
            for section in ['an', 'aa', 'ad']:
                result['section_cache_stats'][section] = {
                    'total': window_section_counts[section],
                    'cached': len(section_cached_keys[section]),
                    'rate': len(section_cached_keys[section]) / window_section_counts[section] * 100 if window_section_counts[section] > 0 else 0,
                }
        else:
            # Unmatched, count cache items
            result['added_stats']['total'] = len(cache['cache_items']['added'])
            result['added_stats']['unknown'] = len(cache['cache_items']['added'])
            result['modified_stats']['total'] = len(cache['cache_items']['modified'])
            result['modified_stats']['unknown'] = len(cache['cache_items']['modified'])
            result['removed_stats']['total'] = len(cache['cache_items']['removed'])

        matched_results.append(result)

    # Group results by cache file
    file_results_map = defaultdict(list)
    for r in matched_results:
        file_results_map[r['cache_file']].append(r)

    # Print aggregated statistics
    print_aggregated_summary(matched_results)

    # Save detailed results
    summary_path = Path.cwd() / 'analysis_summary.json'
    with open(summary_path, 'w') as f:
        json.dump({
            'total_cache_entries': len(matched_results),
            'results': matched_results,
        }, f, indent=2, ensure_ascii=False)
    print(f"\nDetailed results saved to: {summary_path}")


def print_aggregated_summary(matched_results: List[Dict]):
    """
    Print aggregated summary statistics for matching results
    """
    print("\n" + "=" * 80)
    print("Aggregated statistics for all files")
    print("=" * 80)
    print(f"Collected {len(matched_results)} cache data entries")

    # Aggregate by resolver name
    resolver_totals = defaultdict(lambda: {
        'added': defaultdict(int),
        'modified': defaultdict(int),
        'added_total': 0,
        'modified_total': 0,
        'cache_count': 0,
        'matched_count': 0,
        'unmatched_count': 0,
    })

    # Record source resolver file distribution
    resolver_source_distribution = defaultdict(lambda: defaultdict(int))

    # Reverse statistics: ratio of each section's records entering cache
    section_cache_totals = defaultdict(lambda: {
        'an_total': 0, 'an_cached': 0,
        'aa_total': 0, 'aa_cached': 0,
        'ad_total': 0, 'ad_cached': 0,
    })

    # Record files with low source matching ratio
    low_match_files = defaultdict(list)

    # Record unmatched cache data
    unmatched_caches = defaultdict(list)

    for r in matched_results:
        resolver_name = r['resolver_name']

        resolver_totals[resolver_name]['cache_count'] += 1

        if r['matched']:
            resolver_totals[resolver_name]['matched_count'] += 1
            resolver_totals[resolver_name]['added_total'] += r['added_stats']['total']
            resolver_totals[resolver_name]['modified_total'] += r['modified_stats']['total']

            for src in ['an', 'aa', 'ad', 'unknown']:
                resolver_totals[resolver_name]['added'][src] += r['added_stats'][src]
                resolver_totals[resolver_name]['modified'][src] += r['modified_stats'][src]

            # Accumulate reverse statistics
            for section in ['an', 'aa', 'ad']:
                scs = r.get('section_cache_stats', {}).get(section, {})
                section_cache_totals[resolver_name][f'{section}_total'] += scs.get('total', 0)
                section_cache_totals[resolver_name][f'{section}_cached'] += scs.get('cached', 0)

            # Count source resolver file distribution
            for source_info in r['added_stats'].get('sources', []):
                source_file = source_info.get('source_resolver_file')
                if source_file:
                    resolver_source_distribution[resolver_name][source_file] += 1

            # Check source matching ratio
            total = r['added_stats']['total']
            if total > 0:
                matched = r['added_stats']['an'] + r['added_stats']['aa'] + r['added_stats']['ad']
                match_ratio = matched / total
                if match_ratio < 0.9:
                    low_match_files[resolver_name].append({
                        'cache_file': r['cache_file'],
                        'resolver_file': r.get('resolver_file'),
                        'window_resolver_files': r.get('window_resolver_files', []),
                        'trigger_query': f"{r['trigger_query']['qname']} ({r['trigger_query']['qtype']})",
                        'total': total,
                        'matched': matched,
                        'match_ratio': match_ratio,
                        'an': r['added_stats']['an'],
                        'aa': r['added_stats']['aa'],
                        'ad': r['added_stats']['ad'],
                        'unknown': r['added_stats']['unknown'],
                    })
        else:
            resolver_totals[resolver_name]['unmatched_count'] += 1
            unmatched_caches[resolver_name].append({
                'cache_file': r['cache_file'],
                'trigger_query': f"{r['trigger_query']['qname']} ({r['trigger_query']['qtype']})",
                'trigger_timestamp': r['trigger_timestamp'],
            })

    print("\nAggregate by resolver:")
    for resolver_name in sorted(resolver_totals.keys()):
        stats = resolver_totals[resolver_name]
        print(f"\n{resolver_name}:")
        print(f"  Cache data: {stats['cache_count']}, matched: {stats['matched_count']}, unmatched: {stats['unmatched_count']}")

        if stats['matched_count'] > 0:
            if stats['added_total'] > 0:
                total = stats['added_total']
                print(f"  Added total: {total} (matched only)")
                print(f"    an (answers):    {stats['added']['an']:5d} ({stats['added']['an']/total*100:5.1f}%)")
                print(f"    aa (authorities): {stats['added']['aa']:5d} ({stats['added']['aa']/total*100:5.1f}%)")
                print(f"    ad (additionals): {stats['added']['ad']:5d} ({stats['added']['ad']/total*100:5.1f}%)")
                print(f"    ?  (unmatched):      {stats['added']['unknown']:5d} ({stats['added']['unknown']/total*100:5.1f}%)")
            else:
                print(f"  Added total: 0")

            if stats['modified_total'] > 0:
                total = stats['modified_total']
                print(f"  Modified total: {total}")
                print(f"    an: {stats['modified']['an']}, aa: {stats['modified']['aa']}, ad: {stats['modified']['ad']}, ?: {stats['modified']['unknown']}")

            # Reverse statistics: ratio of each section's records entering cache
            scs = section_cache_totals[resolver_name]
            print(f"\n  Reverse statistics (ratio of response records entering cache):")
            for section, section_name in [('an', 'answers'), ('aa', 'authorities'), ('ad', 'additionals')]:
                total = scs[f'{section}_total']
                cached = scs[f'{section}_cached']
                if total > 0:
                    rate = cached / total * 100
                    print(f"    {section} ({section_name}): {cached:5d}/{total:5d} entered cache ({rate:5.1f}%)")
                else:
                    print(f"    {section} ({section_name}): no data")

        # Print unmatched cache
        if resolver_name in unmatched_caches and unmatched_caches[resolver_name]:
            files = unmatched_caches[resolver_name]
            print(f"\n  Cache without corresponding resolver ({len(files)} entries):")
            for f in files[:10]:
                print(f"    {f['cache_file']}: {f['trigger_query']} (ts={f['trigger_timestamp']:.2f})")
            if len(files) > 10:
                print(f"    ... and {len(files)-10} more")

        # Print cache with low source matching ratio
        if resolver_name in low_match_files and low_match_files[resolver_name]:
            files = low_match_files[resolver_name]
            print(f"\n  Cache with source matching ratio <90% ({len(files)} entries):")
            files.sort(key=lambda x: x['match_ratio'])
            for f in files[:10]:
                resolver_file = f.get('resolver_file', 'None')
                print(f"    {f['cache_file']} -> {resolver_file}: {f['trigger_query']} - total={f['total']}, matched={f['matched']} ({f['match_ratio']*100:.1f}%)")
            if len(files) > 10:
                print(f"    ... and {len(files)-10} more")

    # Print source resolver file distribution (which resolver files contributed cache items)
    print("\n" + "=" * 80)
    print("Source Resolver File Distribution (which resolver responses contributed cache items)")
    print("=" * 80)
    for resolver_name in sorted(resolver_source_distribution.keys()):
        dist = resolver_source_distribution[resolver_name]
        total_from_resolvers = sum(dist.values())
        print(f"\n{resolver_name}: {total_from_resolvers} cache items with source records total")
        # Sort by contribution count
        sorted_files = sorted(dist.items(), key=lambda x: -x[1])
        for source_file, count in sorted_files[:10]:
            pct = count / total_from_resolvers * 100 if total_from_resolvers > 0 else 0
            print(f"  {source_file}: {count} ({pct:.1f}%)")
        if len(sorted_files) > 10:
            other_count = sum(c for _, c in sorted_files[10:])
            print(f"  ... {len(sorted_files)-10} other files: {other_count}")

    # Print cache -> resolver file mapping
    print("\n" + "=" * 80)
    print("Cache File -> Resolver File Mapping")
    print("=" * 80)

    # Sort by cache file name
    sorted_results = sorted(matched_results, key=lambda x: (x['resolver_name'], x['cache_file']))
    for r in sorted_results:
        resolver_file = r.get('resolver_file', 'None')
        match_status = "matched" if r['matched'] else "unmatched"
        print(f"  [{r['resolver_name']}] {r['cache_file']} -> {resolver_file} ({match_status})")
        print(f"    trigger: {r['trigger_query']['qname']} ({r['trigger_query']['qtype']})")


if __name__ == '__main__':
    main()