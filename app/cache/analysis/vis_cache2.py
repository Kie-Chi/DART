#!/usr/bin/env python3
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import math

# ==========================================
# Global academic color scheme and style configuration
# ==========================================
# Unified cool-toned color mapping, ensuring all subplots use consistent colors
RESOLVER_DISPLAY_NAMES = {
    'bind': 'bind9.18.0',
    'bind-new': 'bind9.21.15',
    'unbound': 'unbound1.17.1',
    'unbound-new': 'unbound1.24.2',
}

ACADEMIC_COLORS = {
    'an': '#225ea8',      # Deep Navy - Core answers
    'aa': '#41b6c4',      # Teal - Authority records
    'ad': '#a1dab4',      # Soft Green - Additional records
    'unknown': '#d9d9d9'  # Neutral Gray
}

def apply_academic_style(ax):
    """Apply minimalist axis style for top-conference charts: no grid, solid baseline"""
    # Hide top and right borders
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    # Strengthen bottom and left baseline, eliminate floating appearance
    ax.spines['bottom'].set_color('#333333')
    ax.spines['bottom'].set_linewidth(1.5)
    ax.spines['bottom'].set_zorder(5)

    ax.spines['left'].set_color('#333333')
    ax.spines['left'].set_linewidth(1.5)

    # Completely disable grid lines
    ax.grid(False)

def load_data(filepath='analysis_results.json'):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {filepath} not found. Please run the analysis script first.")
        exit(1)

# ==========================================
# Chart 1: Record source distribution (100% stacked bar chart)
# ==========================================
def plot_source_distribution(fwd_data):
    resolvers = sorted(fwd_data.keys())
    display_names = [RESOLVER_DISPLAY_NAMES.get(r, r) for r in resolvers]
    sections = ['an', 'aa', 'ad', 'unknown']
    labels_map = {'an': 'Answers (an)', 'aa': 'Authorities (aa)', 'ad': 'Additionals (ad)', 'unknown': 'Unknown'}

    data_matrix = []
    for r in resolvers:
        total = fwd_data[r]['total']
        data_matrix.append([0,0,0,0] if total == 0 else [fwd_data[r][sec] / total * 100 for sec in sections])

    df = pd.DataFrame(data_matrix, index=display_names, columns=[labels_map[sec] for sec in sections])

    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    colors = [ACADEMIC_COLORS[sec] for sec in sections]

    bottom = np.zeros(len(resolvers))
    for i, col in enumerate(df.columns):
        values = df[col].values
        # Remove edgecolor completely for flat seamless stacking
        ax.bar(display_names, values, bottom=bottom, label=col, color=colors[i], width=0.5, zorder=3)

        # Annotate percentages
        for j, val in enumerate(values):
            if val > 5:
                text_color = 'white' if i < 2 else 'black'
                ax.text(j, bottom[j] + val/2, f'{val:.1f}%', ha='center', va='center',
                        color=text_color, fontweight='medium', fontsize=10)
        bottom += values

    apply_academic_style(ax)
    ax.set_ylabel('Percentage (%)', fontsize=12)
    ax.set_ylim(0, 100)
    ax.set_xticklabels(display_names, fontsize=11)

    ax.legend(loc='upper center', bbox_to_anchor=(0.5, 1.15), ncol=4, frameon=False, fontsize=10)

    plt.tight_layout()
    plt.savefig('chart_1_source_distribution.pdf', format='pdf', bbox_inches='tight')
    plt.close()

# ==========================================
# Chart 2: Cache insertion rate (grouped bar chart)
# ==========================================
def plot_insertion_rates(rev_data):
    resolvers = sorted(rev_data.keys())
    display_names = [RESOLVER_DISPLAY_NAMES.get(r, r) for r in resolvers]
    sections = ['an', 'aa', 'ad']

    rates = {sec: [] for sec in sections}
    for r in resolvers:
        for sec in sections:
            total, cached = rev_data[r][sec]['total'], rev_data[r][sec]['cached']
            rates[sec].append((cached / total * 100) if total > 0 else 0)

    # Compress vertical spacing between resolver groups
    y = np.arange(len(resolvers)) * 0.5
    bar_height = 0.14

    # Widen canvas to extend X-axis display range
    fig, ax = plt.subplots(figsize=(14, 7), dpi=300)

    # Horizontal grouped bar chart: better suited for long labels, allows larger font sizes
    rects1 = ax.barh(y - bar_height, rates['an'], bar_height, label='Answers (an)', color=ACADEMIC_COLORS['an'], zorder=3)
    rects2 = ax.barh(y, rates['aa'], bar_height, label='Authorities (aa)', color=ACADEMIC_COLORS['aa'], zorder=3)
    rects3 = ax.barh(y + bar_height, rates['ad'], bar_height, label='Additionals (ad)', color=ACADEMIC_COLORS['ad'], zorder=3)

    apply_academic_style(ax)
    ax.set_xlabel('Insertion Rate (%)', fontsize=24)
    ax.set_ylabel('Resolver', fontsize=24)
    ax.set_yticks(y)
    ax.set_yticklabels(display_names, fontsize=24)
    ax.tick_params(axis='x', labelsize=22)
    ax.set_xlim(0, 105)
    ax.set_ylim(y[-1] + 0.42, y[0] - 0.42)

    ax.legend(loc='upper center', bbox_to_anchor=(0.5, 1.15), ncol=3, frameon=False, fontsize=22)

    for rects in [rects1, rects2, rects3]:
        for rect in rects:
            width = rect.get_width()
            if width > 0:
                ax.annotate(f'{width:.1f}%',
                            xy=(width, rect.get_y() + rect.get_height() / 2),
                            xytext=(4, 0),
                            textcoords="offset points",
                            ha='left',
                            va='center',
                            fontsize=20)

    # Tighten left/right margins (retain minimal space to avoid label clipping)
    plt.tight_layout(rect=(0.02, 0.02, 0.995, 0.98))
    plt.savefig('chart_2_insertion_rates.pdf', format='pdf', bbox_inches='tight', pad_inches=0.02)
    plt.close()

# ==========================================
# Chart 3: Resolver preference heatmap
# ==========================================
def plot_heatmap(data):
    fwd = data['forward_analysis_cache_to_pcap']
    resolvers = sorted(fwd.keys())
    display_names = [RESOLVER_DISPLAY_NAMES.get(r, r) for r in resolvers]

    matrix = []
    for r in resolvers:
        total = fwd[r]['total']
        matrix.append([0,0,0] if total == 0 else [fwd[r]['an']/total*100, fwd[r]['aa']/total*100, fwd[r]['ad']/total*100])

    df = pd.DataFrame(matrix, index=display_names, columns=['Answers (an)', 'Authorities (aa)', 'Additionals (ad)'])

    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)

    # Heatmap border lines adjusted to be very subtle, highlighting color blocks themselves
    sns.heatmap(df, annot=True, fmt=".1f", cmap="YlGnBu",
                cbar_kws={'label': 'Percentage (%)'}, ax=ax, linewidths=0.5, linecolor='#f0f0f0')

    for t in ax.texts:
        t.set_text(t.get_text() + "%")
        t.set_fontsize(10)

    ax.set_ylabel('Resolver', fontsize=12)
    plt.yticks(rotation=0, fontsize=11)
    plt.xticks(fontsize=11)

    plt.tight_layout()
    plt.savefig('chart_3_preference_heatmap.pdf', format='pdf', bbox_inches='tight')
    plt.close()

# ==========================================
# Chart 4: Cache override state transition heatmap (tilted X-axis + maximally enlarged font version)
# ==========================================
def plot_transition_matrix(fwd_data):
    resolvers = sorted(fwd_data.keys())
    n_resolvers = len(resolvers)

    cols = 2 if n_resolvers > 1 else 1
    rows = math.ceil(n_resolvers / cols)

    # Maintain original canvas proportions
    fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 4 * rows), dpi=300)

    if n_resolvers == 1:
        axes_flat = [axes]
    else:
        axes_flat = axes.flatten()

    states = ['an', 'aa', 'ad', 'unknown']
    labels = ['Answers', 'Authorities', 'Additionals', 'Unknown']

    for idx, r in enumerate(resolvers):
        ax = axes_flat[idx]
        trans_data = fwd_data[r].get('transitions', {})

        matrix = np.zeros((4, 4))
        for i, old_s in enumerate(states):
            for j, new_s in enumerate(states):
                matrix[i, j] = trans_data.get(f"{old_s}_{new_s}", 0)

        df = pd.DataFrame(matrix, index=labels, columns=labels)

        ax.set_facecolor('white')

        blues_cmap = plt.cm.Blues(np.linspace(0.3, 1.0, 256))
        custom_cmap = plt.cm.colors.ListedColormap(blues_cmap)

        # Enlarge heatmap internal numbers to 13
        sns.heatmap(df, annot=True, fmt="g", cmap=custom_cmap, ax=ax,
                    mask=(df==0),
                    cbar_kws={'label': 'Record Count'},
                    annot_kws={"size": 13},
                    linewidths=0)

        ax.grid(True, color='#d3d3d3', linestyle='-', linewidth=1)
        ax.set_axisbelow(True)

        # Enlarge title
        ax.set_title(f'{RESOLVER_DISPLAY_NAMES.get(r, r)}', fontsize=15, pad=12, fontweight='bold')

        # Enlarge axis labels
        ax.set_ylabel('OLD Source', fontsize=14)
        ax.set_xlabel('NEW Source', fontsize=14)

        # [Key change]: Tilt X-axis labels 45 degrees, use anchor alignment, enlarge font to 13
        ax.set_xticklabels(labels, rotation=45, ha='right', rotation_mode='anchor', fontsize=13)

        # Keep Y-axis labels horizontal, also enlarge to 13
        ax.set_yticklabels(labels, rotation=0, fontsize=13)

        # Enlarge colorbar font
        cbar = ax.collections[0].colorbar
        cbar.ax.tick_params(labelsize=11)
        cbar.set_label('Record Count', size=13)

    for idx in range(n_resolvers, len(axes_flat)):
        axes_flat[idx].set_visible(False)

    # tight_layout automatically calculates margin space, ensuring tilted text is not clipped by PDF edges
    plt.tight_layout()
    plt.savefig('chart_4_transition_matrix.pdf', format='pdf', bbox_inches='tight')
    plt.close()

if __name__ == '__main__':
    data = load_data()

    # Force seaborn background to pure white, without any default grid style
    sns.set_theme(style="white")

    plot_source_distribution(data['forward_analysis_cache_to_pcap'])
    plot_insertion_rates(data['reverse_analysis_pcap_to_cache'])
    plot_heatmap(data)
    plot_transition_matrix(data['forward_analysis_cache_to_pcap'])