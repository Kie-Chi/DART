import json
import glob
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import requests
import socket

sns.set_theme(style="whitegrid")
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['font.family'] = ['DejaVu Sans', 'sans-serif']


# DNS RCODE standard mapping table
RCODE_MAP = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
    # 11-15 are reserved values
    16: "BADVERS/BADSIG", # EDNS
}

def get_rcode_name(code):
    """
    Convert RCODE to a name.
    If numeric, look up the table; if unknown numeric, return RCODE_N; if already a string, return as-is.
    """
    if code is None:
        return "UNKNOWN"
    if code == "NO_RESPONSE":
        return "NO_RESPONSE"
    
    # If already a string (e.g., some logs have already been converted), return uppercased directly
    if isinstance(code, str):
        # Try to determine if it's a numeric string like "0"
        if code.isdigit():
            code = int(code)
        else:
            return code.upper()

    # If numeric, look up the table
    if isinstance(code, int):
        return RCODE_MAP.get(code, f"RCODE_{code}")
    
    return str(code)

def load_data(data_dir):
    """
    Load data and automatically convert numeric RCODEs to readable strings.
    """
    summary_records = []
    step_records = []
    
    files = glob.glob(os.path.join(data_dir, "analyze_*.json"))
    print(f"Found {len(files)} files. Loading...")
    
    for file_path in files:
        try:
            filename = Path(file_path).stem
            try:
                iteration_id = filename.split('_')[1]
            except IndexError:
                iteration_id = filename
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content: continue
                data = json.loads(content)
                
            for resolver_key, result in data.items():
                resolver_name = resolver_key.replace("resolver:", "")
                
                # --- 1. Process Summary data ---
                tx = result.get("transaction") or {}
                
                # Convert Summary-level RCODE
                raw_final_rcode = tx.get("rcode")
                final_rcode_name = get_rcode_name(raw_final_rcode)
                
                if result.get("status") == "error":
                    summary_records.append({
                        "iteration": iteration_id,
                        "resolver": resolver_name,
                        "status": "error",
                        "final_rcode": "INTERNAL_ERROR",
                        "total_duration": 0,
                        "step_count": 0
                    })
                    continue

                path = tx.get("analyzed_path") or {}
                steps = path.get("steps") or []
                
                summary_records.append({
                    "iteration": iteration_id,
                    "resolver": resolver_name,
                    "status": "success",
                    "final_rcode": final_rcode_name, # Use converted name
                    "total_duration": tx.get("duration", 0),
                    "step_count": len(steps)
                })

                # --- 2. Process Steps data ---
                for step_idx, step in enumerate(steps):
                    if not step: continue
                    query = step.get("query") or {}
                    response = step.get("response") or {}
                    
                    # Convert upstream response RCODE
                    raw_upstream_rcode = response.get("rcode", "NO_RESPONSE")
                    upstream_rcode_name = get_rcode_name(raw_upstream_rcode)
                    
                    step_records.append({
                        "iteration": iteration_id,
                        "resolver": resolver_name,
                        "step_index": step_idx,
                        "upstream_qname": query.get("qname", "UNKNOWN"),
                        "upstream_qtype": query.get("qtype", "UNKNOWN"),
                        "upstream_dst_ip": query.get("dst_ip", "UNKNOWN"),
                        "upstream_rcode": upstream_rcode_name, # Use converted name
                        "step_duration": step.get("duration", 0)
                    })
                
        except json.JSONDecodeError:
            print(f"Skipping invalid JSON file: {file_path}")
        except Exception as e:
            print(f"Warning: Error processing {file_path}: {str(e)}")
            
    return pd.DataFrame(summary_records), pd.DataFrame(step_records)

def viz_1_performance_and_steps(df_summary, output_dir):
    """1. Average request duration and average resolution steps (fixed alignment issue)"""
    if df_summary.empty: return
    success_df = df_summary[df_summary['status'] == 'success']
    if success_df.empty: return

    stats = success_df.groupby('resolver')[['total_duration', 'step_count']].mean().reset_index()
    
    fig, ax1 = plt.subplots(figsize=(12, 6))
    
    sns.barplot(data=stats, x='resolver', y='total_duration', ax=ax1, 
                color='skyblue', alpha=0.6, label=t('Avg total duration (s)'), zorder=2)
    ax1.set_ylabel(t('Avg total duration (s)'))
    ax1.set_xlabel(t('Resolver'))
    ax1.grid(True, axis='y', linestyle='--', alpha=0.7, zorder=0) # Explicitly enable left axis grid
    
    ax2 = ax1.twinx()
    sns.pointplot(data=stats, x='resolver', y='step_count', ax=ax2, 
                  color='red', markers='o', scale=0.8, label=t('Avg upstream query count'), zorder=3)
    
    ax2.set_ylabel(t('Avg upstream query count (steps)'))
    ax2.set_ylim(bottom=0)
    
    ax2.grid(False)
    
    plt.title(t('Resolver performance profile'))
    handles1, labels1 = ax1.get_legend_handles_labels()
    import matplotlib.lines as mlines
    line_proxy = mlines.Line2D([], [], color='red', marker='o', markersize=6, label=t('Avg upstream query count'))
    
    ax1.legend(handles=[handles1[0], line_proxy], labels=[labels1[0], t('Avg upstream query count')], loc='upper left')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '1_perf_and_steps.png'), dpi=300) # Increase resolution
    plt.close()

def viz_2_final_result_ratio(df_summary, output_dir):
    """2. Resolver final response type ratio"""
    if df_summary.empty: return
    # Compute the final RCODE distribution for each resolver
    cross_tab = pd.crosstab(df_summary['resolver'], df_summary['final_rcode'], normalize='index')
    
    if cross_tab.empty: return

    ax = cross_tab.plot(kind='bar', stacked=True, figsize=(12, 6), colormap='tab20')
    plt.title(t('Final response RCODE ratio by resolver'))
    plt.ylabel(t('Ratio'))
    plt.xlabel(t('Resolver'))
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', title="RCODE")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '2_final_rcode_ratio.png'), dpi=300)
    plt.close()

def viz_3_upstream_qtype_fingerprint(df_steps, output_dir):
    """3. Resolver upstream request type composition (core requirement)"""
    if df_steps.empty:
        print("No steps data available for upstream analysis.")
        return

    # Compute QTYPE distribution
    qtype_dist = pd.crosstab(df_steps['resolver'], df_steps['upstream_qtype'], normalize='index')
    
    if qtype_dist.empty: return

    ax = qtype_dist.plot(kind='bar', stacked=True, figsize=(14, 7), colormap='Set2')
    
    plt.title(t('Upstream query behavior'))
    plt.ylabel(t('Ratio'))
    plt.xlabel(t('Resolver'))
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', title="Upstream QTYPE")
    
    # Annotate values
    for c in ax.containers:
        labels = [f'{v.get_height():.1%}' if v.get_height() > 0.05 else '' for v in c]
        ax.bar_label(c, labels=labels, label_type='center', fontsize=8)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '3_upstream_qtype_fingerprint.png'), dpi=300)
    plt.close()

def viz_4_upstream_rcode_distribution(df_steps, output_dir):
    """
    - NO_RESPONSE: upstream timeout/packet loss (possibly caused by packets sent by the Fuzzer that the upstream doesn't reply to)
    - FORMERR: the resolver sent a malformed packet (this is the Bug that Fuzzing aims to find!)
    - REFUSED/SERVFAIL: upstream refused to process
    """
    if df_steps.empty: return
    rcode_dist = pd.crosstab(df_steps['resolver'], df_steps['upstream_rcode'], normalize='index')
    
    if rcode_dist.empty: return

    # Plot
    ax = rcode_dist.plot(kind='bar', stacked=True, figsize=(14, 7), colormap='tab20c')
    
    plt.title(t('Upstream interaction status distribution'))
    plt.ylabel(t('Ratio'))
    plt.xlabel(t('Resolver'))
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', title="Upstream RCODE")
    
    for c in ax.containers:
        labels = [f'{v.get_height():.1%}' if v.get_height() > 0.02 else '' for v in c]
        ax.bar_label(c, labels=labels, label_type='center', fontsize=8, color='white')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '4_upstream_rcode_distribution.png'), dpi=300)
    plt.close()

def get_ip_metadata(ip_list):
    """
    Input an IP list and return a mapping dictionary.
    [Modification] Only return the Hostname (if present), completely removing IP and newlines for cleaner charts.
    """
    ip_map = {}
    print(f"Fetching hostname info for {len(ip_list)} top IPs...")
    
    # Set socket timeout to prevent reverse DNS resolution from hanging too long
    socket.setdefaulttimeout(2)
    
    for ip in ip_list:
        hostname = None
        source_type = "Raw IP"
        
        # --- Strategy 1: Prefer reverse DNS resolution (PTR) ---
        try:
            ptr_result = socket.gethostbyaddr(ip)
            hostname = ptr_result[0]
            
            # Remove trailing dot that may exist in DNS names
            if hostname.endswith('.'):
                hostname = hostname[:-1]
                
            source_type = "Hostname"
            
        except (socket.herror, socket.gaierror, socket.timeout):
            # --- Strategy 2: PTR failed, try API to get organization name as fallback ---
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}?fields=org,isp", timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    hostname = data.get("org") or data.get("isp")
                    source_type = "Org(Fallback)"
            except Exception:
                pass
        
        # --- Format label ---
        if hostname:
            # If the name is too long, truncate to the last 3 segments for cleaner charts
            if len(hostname) > 30 and source_type == "Hostname":
                parts = hostname.split('.')
                if len(parts) > 3:
                    hostname = "..." + ".".join(parts[-3:])
            
            # [Core modification] Only use the Hostname, without brackets or concatenated IP
            label = hostname
        else:
            # If unable to obtain a Hostname, fall back to displaying the IP
            label = ip
            
        ip_map[ip] = label
        print(f"  - {ip} -> {hostname if hostname else 'No Hostname'} [{source_type}]")
        
    return ip_map

def viz_5_target_ip_heatmap(df_steps, output_dir):
    """5. Upstream target IP heatmap (academic paper version - with version numbers and larger fonts)"""
    if df_steps.empty: return
    
    # --- New: Resolver version number mapping table ---
    RESOLVER_NAME_MAP = {
        'bind': 'bind9.18.0',
        'bind-new': 'bind9.21.15',
        'unbound': 'unbound1.17.1',
        'unbound-new': 'unbound1.24.2',
        'pdns_recursor': 'pdns4.5.4',
        'pdns_recursor-new': 'pdns5.2.6',
        'knot_resolver': 'knot5.5.2',
        'knot_resolver-new': 'knot6.0.16'
    }

    # 1. Compute Top 15 IPs
    top_ips_series = df_steps['upstream_dst_ip'].value_counts().nlargest(15)
    top_ips = top_ips_series.index.tolist()
    
    if len(top_ips) == 0: return

    # 2. Get metadata (Hostname preferred)
    ip_labels_map = get_ip_metadata(top_ips)

    # 3. Filter and replace
    filtered_df = df_steps[df_steps['upstream_dst_ip'].isin(top_ips)].copy()
    filtered_df['ip_label'] = filtered_df['upstream_dst_ip'].map(ip_labels_map)
    
    # 4. Build pivot table
    heatmap_data = pd.crosstab(filtered_df['ip_label'], filtered_df['resolver'])
    
    # --- New: Replace column names with full version names ---
    heatmap_data.rename(columns=RESOLVER_NAME_MAP, inplace=True)
    
    # 5. Sort: sort Y axis by total request count descending
    sorted_labels = [ip_labels_map[ip] for ip in top_ips]
    heatmap_data = heatmap_data.reindex(sorted_labels)

    # Slightly widen the canvas to accommodate longer bottom labels
    plt.figure(figsize=(11, 8), dpi=300)
    
    # Draw heatmap and enlarge internal annotation font
    ax = sns.heatmap(heatmap_data, annot=True, fmt='d', cmap='YlGnBu', linewidths=.5,
                     annot_kws={"size": 15}) # Enlarge numbers inside cells
    
    # Enlarge axis title font
    plt.ylabel(t('Authoritative Target'), fontsize=15, fontweight='medium')
    plt.xlabel(t('Resolver'), fontsize=15, fontweight='medium')
    
    # Enlarge tick labels; keep X axis at 45 degrees to prevent overlap
    plt.xticks(rotation=45, ha='right', fontsize=19)
    plt.yticks(rotation=0, fontsize=17)
    
    # Get the Colorbar object and separately enlarge its font
    cbar = ax.collections[0].colorbar
    cbar.ax.tick_params(labelsize=12)
    cbar.set_label(t('Request Count'), size=17)
    
    plt.tight_layout()
    
    plt.savefig(os.path.join(output_dir, '5_upstream_target_ip_heatmap.pdf'), format='pdf', bbox_inches='tight')
    plt.savefig(os.path.join(output_dir, '5_upstream_target_ip_heatmap.png'), dpi=300, bbox_inches='tight')
    plt.close()

if __name__ == "__main__":
    DATA_DIR = "./fuzzer_output/analyze" 
    OUTPUT_DIR = "./visualizations"
    
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    print("Step 1: Loading and processing data...")
    df_sum, df_stp = load_data(DATA_DIR)
    
    if not df_sum.empty:
        print(f"Loaded {len(df_sum)} transactions and {len(df_stp)} upstream steps.")
        print("Step 2: Generating visualizations...")
        
        viz_1_performance_and_steps(df_sum, OUTPUT_DIR)
        viz_2_final_result_ratio(df_sum, OUTPUT_DIR)
        viz_3_upstream_qtype_fingerprint(df_stp, OUTPUT_DIR)
        viz_4_upstream_rcode_distribution(df_stp, OUTPUT_DIR)
        viz_5_target_ip_heatmap(df_stp, OUTPUT_DIR)
        
        print(f"All done! Check {OUTPUT_DIR}")
    else:
        print("No valid data found or all files were errors.")