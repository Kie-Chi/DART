#!/usr/bin/env python3
"""
Visualization analysis results script
Reads data from analysis.log or analysis_summary.json and generates visualization charts

Usage:
    python visualize_analysis.py analysis.log
    python visualize_analysis.py analysis_summary.json
"""

import sys
import re
import json
from pathlib import Path
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.ticker import PercentFormatter

sns.set_theme(style="whitegrid")
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['font.family'] = ['DejaVu Sans', 'sans-serif']


def parse_log_file(log_path: Path) -> dict:
    """
    Parse analysis.log file and extract statistics
    """
    with open(log_path, 'r') as f:
        content = f.read()

    results = {}

    # Parse statistics for each resolver
    resolver_pattern = re.compile(
        r'(\w+-?\w*):\s*\n'
        r'  Cache data: (\d+), matched: (\d+), unmatched: (\d+)\s*\n'
        r'  Added total: (\d+) \(matched only\)\s*\n'
        r'    an \(answers\):\s*(\d+)\s*\(\s*([\d.]+)%\)\s*\n'
        r'    aa \(authorities\):\s*(\d+)\s*\(\s*([\d.]+)%\)\s*\n'
        r'    ad \(additionals\):\s*(\d+)\s*\(\s*([\d.]+)%\)\s*\n'
        r'    \?  \(unmatched\):\s*(\d+)\s*\(\s*([\d.]+)%\)'
    )

    for match in resolver_pattern.finditer(content):
        resolver_name = match.group(1)
        results[resolver_name] = {
            'cache_count': int(match.group(2)),
            'matched_count': int(match.group(3)),
            'unmatched_count': int(match.group(4)),
            'added_total': int(match.group(5)),
            'an': {'count': int(match.group(6)), 'pct': float(match.group(7))},
            'aa': {'count': int(match.group(8)), 'pct': float(match.group(9))},
            'ad': {'count': int(match.group(10)), 'pct': float(match.group(11))},
            'unknown': {'count': int(match.group(12)), 'pct': float(match.group(13))},
        }

    return results


def parse_json_file(json_path: Path) -> dict:
    """
    Parse analysis_summary.json file and extract statistics
    """
    with open(json_path, 'r') as f:
        data = json.load(f)

    results = defaultdict(lambda: {
        'cache_count': 0,
        'matched_count': 0,
        'unmatched_count': 0,
        'added_total': 0,
        'an': {'count': 0, 'pct': 0},
        'aa': {'count': 0, 'pct': 0},
        'ad': {'count': 0, 'pct': 0},
        'unknown': {'count': 0, 'pct': 0},
    })

    for r in data.get('results', []):
        resolver_name = r['resolver_name']
        results[resolver_name]['cache_count'] += 1

        if r['matched']:
            results[resolver_name]['matched_count'] += 1
            results[resolver_name]['added_total'] += r['added_stats']['total']
            results[resolver_name]['an']['count'] += r['added_stats']['an']
            results[resolver_name]['aa']['count'] += r['added_stats']['aa']
            results[resolver_name]['ad']['count'] += r['added_stats']['ad']
            results[resolver_name]['unknown']['count'] += r['added_stats']['unknown']
        else:
            results[resolver_name]['unmatched_count'] += 1

    # Calculate percentages
    for resolver_name in results:
        total = results[resolver_name]['added_total']
        if total > 0:
            results[resolver_name]['an']['pct'] = results[resolver_name]['an']['count'] / total * 100
            results[resolver_name]['aa']['pct'] = results[resolver_name]['aa']['count'] / total * 100
            results[resolver_name]['ad']['pct'] = results[resolver_name]['ad']['count'] / total * 100
            results[resolver_name]['unknown']['pct'] = results[resolver_name]['unknown']['count'] / total * 100

    return dict(results)


def create_visualizations(results: dict, output_dir: Path):
    """
    Create visualization charts
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    resolvers = sorted(results.keys())

    # Prepare data
    data_rows = []
    for resolver in resolvers:
        r = results[resolver]
        data_rows.append({
            'resolver': resolver,
            'an': r['an']['pct'] / 100,  # Convert to proportion
            'aa': r['aa']['pct'] / 100,
            'ad': r['ad']['pct'] / 100,
            'unknown': r['unknown']['pct'] / 100,
            'an_count': r['an']['count'],
            'aa_count': r['aa']['count'],
            'ad_count': r['ad']['count'],
            'unknown_count': r['unknown']['count'],
            'total': r['added_total'],
        })

    df = pd.DataFrame(data_rows)

    # Chart 1: Added distribution grouped bar chart (similar to source_1_added_distribution.png)
    fig1, ax1 = plt.subplots(figsize=(12, 7))

    categories = ['an', 'aa', 'ad', 'unknown']
    category_labels = [
        'Answers (an)',
        'Authorities (aa)',
        'Additionals (ad)',
        'Unknown'
    ]
    colors = ['#3498db', '#e67e22', '#9b59b6', '#95a5a6']

    x = range(len(resolvers))
    width = 0.2

    for i, (cat, label, color) in enumerate(zip(categories, category_labels, colors)):
        values = df[cat].values
        bars = ax1.bar([xi + i * width - 1.5 * width for xi in x], values, width,
                       label=label, color=color, alpha=0.85)

        # Add value labels
        for bar, val in zip(bars, values):
            ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f'{val:.1%}', ha='center', va='bottom', fontsize=9)

    ax1.set_xlabel('Resolver', fontsize=12)
    ax1.set_ylabel('Percentage', fontsize=12)
    ax1.set_title('Cache Added Records Source Distribution', fontsize=14)
    ax1.set_xticks(x)
    ax1.set_xticklabels(resolvers, fontsize=11)
    ax1.legend(loc='upper right', fontsize=10)
    ax1.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax1.set_ylim(0, 0.55)

    plt.tight_layout()
    fig1.savefig(output_dir / 'source_1_added_distribution.png', dpi=300)
    plt.close(fig1)
    print(f"Saved: {output_dir / 'source_1_added_distribution.png'}")

    # Chart 2: Modified distribution grouped bar chart
    fig2, ax2 = plt.subplots(figsize=(12, 7))

    for i, (cat, label, color) in enumerate(zip(categories, category_labels, colors)):
        # Modified data structure is similar, but we retrieve from results again
        pass

    # Chart 3: Stacked bar chart
    fig3, ax3 = plt.subplots(figsize=(12, 7))

    bottom = [0] * len(resolvers)
    for cat, label, color in zip(categories, category_labels, colors):
        values = df[cat].values
        ax3.bar(x, values, 0.6, label=label, bottom=bottom, color=color, alpha=0.85)

        # Add labels
        for j, (b, v) in enumerate(zip(bottom, values)):
            if v > 0.05:  # Only annotate portions greater than 5%
                ax3.text(j, b + v / 2, f'{v:.1%}', ha='center', va='center',
                        fontsize=9, color='white', fontweight='bold')
        bottom = [b + v for b, v in zip(bottom, values)]

    ax3.set_xlabel('Resolver', fontsize=12)
    ax3.set_ylabel('Percentage', fontsize=12)
    ax3.set_title('Cache Added Records Source Distribution (Stacked)', fontsize=14)
    ax3.set_xticks(x)
    ax3.set_xticklabels(resolvers, fontsize=11)
    ax3.legend(loc='upper right', fontsize=10)
    ax3.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax3.set_ylim(0, 1.0)

    plt.tight_layout()
    fig3.savefig(output_dir / 'source_2_added_stacked.png', dpi=300)
    plt.close(fig3)
    print(f"Saved: {output_dir / 'source_2_added_stacked.png'}")

    # Chart 4: Absolute count bar chart
    fig4, ax4 = plt.subplots(figsize=(12, 7))

    count_categories = ['an_count', 'aa_count', 'ad_count', 'unknown_count']

    for i, (cat, label, color) in enumerate(zip(count_categories, category_labels, colors)):
        values = df[cat].values
        ax4.bar([xi + i * width - 1.5 * width for xi in x], values, width,
                label=label, color=color, alpha=0.85)

    ax4.set_xlabel('Resolver', fontsize=12)
    ax4.set_ylabel('Record Count', fontsize=12)
    ax4.set_title('Cache Added Records Source Count', fontsize=14)
    ax4.set_xticks(x)
    ax4.set_xticklabels(resolvers, fontsize=11)
    ax4.legend(loc='upper right', fontsize=10)

    plt.tight_layout()
    fig4.savefig(output_dir / 'source_3_added_counts.png', dpi=300)
    plt.close(fig4)
    print(f"Saved: {output_dir / 'source_3_added_counts.png'}")

    # Chart 5: Overall pie chart
    fig5, ax5 = plt.subplots(figsize=(10, 10))

    total_an = sum(results[r]['an']['count'] for r in resolvers)
    total_aa = sum(results[r]['aa']['count'] for r in resolvers)
    total_ad = sum(results[r]['ad']['count'] for r in resolvers)
    total_unknown = sum(results[r]['unknown']['count'] for r in resolvers)
    total_all = total_an + total_aa + total_ad + total_unknown

    sizes = [total_an, total_aa, total_ad, total_unknown]
    explode = (0.02, 0.02, 0.02, 0.05)  # Highlight unknown

    wedges, texts, autotexts = ax5.pie(sizes, explode=explode, labels=category_labels,
                                        colors=colors, autopct='%1.1f%%', startangle=90,
                                        textprops={'fontsize': 11})
    ax5.set_title(f'All Resolvers Combined ({total_all:,} records)', fontsize=14)

    plt.tight_layout()
    fig5.savefig(output_dir / 'source_4_total_pie.png', dpi=300)
    plt.close(fig5)
    print(f"Saved: {output_dir / 'source_4_total_pie.png'}")

    # Chart 6: Individual pie charts per resolver
    fig6, axes = plt.subplots(2, 2, figsize=(14, 12))

    for idx, resolver in enumerate(resolvers):
        ax = axes[idx % 2, idx // 2]
        r = results[resolver]
        sizes = [r['an']['count'], r['aa']['count'], r['ad']['count'], r['unknown']['count']]
        total = sum(sizes)

        ax.pie(sizes, labels=category_labels, colors=colors, autopct='%1.1f%%',
               startangle=90, textprops={'fontsize': 9})
        ax.set_title(f'{resolver} ({total:,} records)', fontsize=12)

    plt.suptitle('Cache Added Source Distribution by Resolver',
                 fontsize=14, y=1.02)
    plt.tight_layout()
    fig6.savefig(output_dir / 'source_5_resolver_pies.png', dpi=300, bbox_inches='tight')
    plt.close(fig6)
    print(f"Saved: {output_dir / 'source_5_resolver_pies.png'}")

    # Chart 7: BIND vs Unbound comparison
    fig7, axes7 = plt.subplots(1, 2, figsize=(14, 6))

    # bind vs bind-new
    ax = axes7[0]
    bind_resolvers = [r for r in ['bind', 'bind-new'] if r in results]
    if len(bind_resolvers) == 2:
        for i, resolver in enumerate(bind_resolvers):
            values = [results[resolver][cat]['pct'] / 100 for cat in categories]
            ax.bar([xi + i * width - width / 2 for xi in range(len(categories))],
                   values, width, label=resolver, alpha=0.85)
        ax.set_xlabel('Source', fontsize=11)
        ax.set_ylabel('Percentage', fontsize=11)
        ax.set_title('BIND vs BIND-NEW', fontsize=12)
        ax.set_xticks(range(len(categories)))
        ax.set_xticklabels(['an', 'aa', 'ad', '?'], fontsize=10)
        ax.legend(fontsize=10)
        ax.yaxis.set_major_formatter(PercentFormatter(1.0))
        ax.set_ylim(0, 0.55)

    # unbound vs unbound-new
    ax = axes7[1]
    unbound_resolvers = [r for r in ['unbound', 'unbound-new'] if r in results]
    if len(unbound_resolvers) == 2:
        for i, resolver in enumerate(unbound_resolvers):
            values = [results[resolver][cat]['pct'] / 100 for cat in categories]
            ax.bar([xi + i * width - width / 2 for xi in range(len(categories))],
                   values, width, label=resolver, alpha=0.85)
        ax.set_xlabel('Source', fontsize=11)
        ax.set_ylabel('Percentage', fontsize=11)
        ax.set_title('Unbound vs Unbound-NEW', fontsize=12)
        ax.set_xticks(range(len(categories)))
        ax.set_xticklabels(['an', 'aa', 'ad', '?'], fontsize=10)
        ax.legend(fontsize=10)
        ax.yaxis.set_major_formatter(PercentFormatter(1.0))
        ax.set_ylim(0, 0.55)

    plt.tight_layout()
    fig7.savefig(output_dir / 'source_6_resolver_comparison.png', dpi=300)
    plt.close(fig7)
    print(f"Saved: {output_dir / 'source_6_resolver_comparison.png'}")

    # Chart 8: Heatmap
    fig8, ax8 = plt.subplots(figsize=(10, 6))

    heatmap_data = df.set_index('resolver')[categories] * 100  # Convert to percentages
    heatmap_data.columns = ['an (%)', 'aa (%)', 'ad (%)', 'unknown (%)']

    sns.heatmap(heatmap_data, annot=True, fmt='.1f', cmap='YlOrRd',
                ax=ax8, linewidths=0.5, cbar_kws={'format': '%.0f%%'})

    ax8.set_title('Cache Added Source Distribution Heatmap', fontsize=14)
    ax8.set_xlabel('Source', fontsize=12)
    ax8.set_ylabel('Resolver', fontsize=12)

    plt.tight_layout()
    fig8.savefig(output_dir / 'source_7_heatmap.png', dpi=300)
    plt.close(fig8)
    print(f"Saved: {output_dir / 'source_7_heatmap.png'}")

    # Chart 9: Cache matching status
    fig9, ax9 = plt.subplots(figsize=(10, 6))

    matched_counts = [results[r]['matched_count'] for r in resolvers]
    unmatched_counts = [results[r]['unmatched_count'] for r in resolvers]
    total_counts = [results[r]['cache_count'] for r in resolvers]

    x = range(len(resolvers))
    width = 0.25

    ax9.bar([xi - width for xi in x], total_counts, width,
            label='Total', color='#3498db', alpha=0.85)
    ax9.bar(x, matched_counts, width,
            label='Matched', color='#2ecc71', alpha=0.85)
    ax9.bar([xi + width for xi in x], unmatched_counts, width,
            label='Unmatched', color='#e74c3c', alpha=0.85)

    ax9.set_xlabel('Resolver', fontsize=12)
    ax9.set_ylabel('Count', fontsize=12)
    ax9.set_title('Cache Matching Status', fontsize=14)
    ax9.set_xticks(x)
    ax9.set_xticklabels(resolvers, fontsize=11)
    ax9.legend(fontsize=10)

    plt.tight_layout()
    fig9.savefig(output_dir / 'source_8_matching_status.png', dpi=300)
    plt.close(fig9)
    print(f"Saved: {output_dir / 'source_8_matching_status.png'}")

    # Print summary statistics
    print("\n" + "=" * 70)
    print("Summary Statistics")
    print("=" * 70)
    for resolver in resolvers:
        r = results[resolver]
        print(f"\n{resolver}:")
        print(f"  Cache entries: {r['cache_count']}, matched: {r['matched_count']}")
        print(f"  Total Added: {r['added_total']}")
        print(f"    an: {r['an']['count']:6d} ({r['an']['pct']:5.1f}%)")
        print(f"    aa: {r['aa']['count']:6d} ({r['aa']['pct']:5.1f}%)")
        print(f"    ad: {r['ad']['count']:6d} ({r['ad']['pct']:5.1f}%)")
        print(f"    ?:  {r['unknown']['count']:6d} ({r['unknown']['pct']:5.1f}%)")

    print(f"\nAll Resolvers Summary:")
    print(f"  Total cache items: {total_all:,}")
    print(f"    an: {total_an:,} ({total_an/total_all*100:.1f}%)")
    print(f"    aa: {total_aa:,} ({total_aa/total_all*100:.1f}%)")
    print(f"    ad: {total_ad:,} ({total_ad/total_all*100:.1f}%)")
    print(f"    ?:  {total_unknown:,} ({total_unknown/total_all*100:.1f}%)")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python visualize_analysis.py <analysis.log|analysis_summary.json>")
        sys.exit(1)

    input_path = Path(sys.argv[1])

    if not input_path.exists():
        print(f"Error: file not found {input_path}")
        sys.exit(1)

    # Choose parsing method based on file type
    if input_path.suffix == '.json':
        results = parse_json_file(input_path)
        print(f"Reading data from JSON file: {input_path}")
    else:
        results = parse_log_file(input_path)
        print(f"Reading data from LOG file: {input_path}")

    if not results:
        print(f"Error: Could not extract statistics from file")
        sys.exit(1)

    print(f"Found {len(results)} resolvers with statistics: {sorted(results.keys())}")

    # Create visualizations
    output_dir = Path.cwd() / 'analysis_visualization'
    create_visualizations(results, output_dir)

    print(f"\nAll charts saved to: {output_dir}")


if __name__ == '__main__':
    main()