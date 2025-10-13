#!/usr/bin/env python3
"""
OP-TEE System-Level Performance Visualizer
Generates meaningful system resource utilization graphs
Usage: python3 visualize_performance.py <csv_file>
"""

import pandas as pd
import matplotlib.pyplot as plt
import sys
import os

def plot_performance_data(csv_file):
    """Generate system-level performance visualization from CSV data"""
    
    try:
        df = pd.read_csv(csv_file)
        print(f"Successfully loaded {len(df)} data points from {csv_file}")
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return
    
    # Create figure with subplots
    fig = plt.figure(figsize=(18, 12))
    gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
    
    fig.suptitle(f'OP-TEE System-Level Performance Analysis\n{os.path.basename(csv_file)}', 
                 fontsize=16, fontweight='bold')
    
    # Convert to seconds
    df['Elapsed_sec'] = df['Elapsed_ms'] / 1000.0
    
    # Convert KB to MB for memory
    df['Process_RSS_MB'] = df['Process_RSS_KB'] / 1024.0
    df['System_Used_MB'] = df['System_Used_KB'] / 1024.0
    df['System_Available_MB'] = df['System_Available_KB'] / 1024.0
    df['System_Total_MB'] = df['System_Total_KB'] / 1024.0
    
    # Plot 1: System CPU Utilization (TOP LEFT - MOST IMPORTANT)
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.plot(df['Elapsed_sec'], df['System_CPU_Percent'], 'b-', linewidth=2, label='System CPU')
    ax1.fill_between(df['Elapsed_sec'], df['System_CPU_Percent'], alpha=0.3, color='blue')
    ax1.set_xlabel('Time (seconds)', fontsize=10)
    ax1.set_ylabel('CPU Utilization (%)', fontsize=10)
    ax1.set_title('Overall System CPU Utilization', fontsize=12, fontweight='bold')
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim([0, 105])
    ax1.axhline(y=50, color='orange', linestyle='--', alpha=0.5, label='50% threshold')
    ax1.axhline(y=80, color='red', linestyle='--', alpha=0.5, label='80% threshold')
    ax1.legend(loc='upper right', fontsize=8)
    
    # Plot 2: Process CPU Contribution (TOP MIDDLE)
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.plot(df['Elapsed_sec'], df['Process_CPU_Percent'], 'g-', linewidth=2)
    ax2.fill_between(df['Elapsed_sec'], df['Process_CPU_Percent'], alpha=0.3, color='green')
    ax2.set_xlabel('Time (seconds)', fontsize=10)
    ax2.set_ylabel('Process CPU (%)', fontsize=10)
    ax2.set_title('OP-TEE Process CPU Usage\n(% of Total System CPU)', fontsize=12, fontweight='bold')
    ax2.grid(True, alpha=0.3)
    ax2.set_ylim(bottom=0)
    
    # Plot 3: CPU Usage Comparison (TOP RIGHT)
    ax3 = fig.add_subplot(gs[0, 2])
    ax3.plot(df['Elapsed_sec'], df['System_CPU_Percent'], 'b-', linewidth=2, label='Total System', alpha=0.7)
    ax3.plot(df['Elapsed_sec'], df['Process_CPU_Percent'], 'g-', linewidth=2, label='OP-TEE Process', alpha=0.7)
    ax3.set_xlabel('Time (seconds)', fontsize=10)
    ax3.set_ylabel('CPU Usage (%)', fontsize=10)
    ax3.set_title('CPU Usage Comparison', fontsize=12, fontweight='bold')
    ax3.grid(True, alpha=0.3)
    ax3.legend(loc='upper right', fontsize=9)
    
    # Plot 4: System Memory Utilization (MIDDLE LEFT)
    ax4 = fig.add_subplot(gs[1, 0])
    ax4.plot(df['Elapsed_sec'], df['System_Used_Percent'], 'r-', linewidth=2, label='Used')
    ax4.plot(df['Elapsed_sec'], df['System_Available_Percent'], 'm-', linewidth=2, label='Available')
    ax4.fill_between(df['Elapsed_sec'], df['System_Used_Percent'], alpha=0.2, color='red')
    ax4.set_xlabel('Time (seconds)', fontsize=10)
    ax4.set_ylabel('Memory Utilization (%)', fontsize=10)
    ax4.set_title('System Memory Utilization', fontsize=12, fontweight='bold')
    ax4.grid(True, alpha=0.3)
    ax4.set_ylim([0, 105])
    ax4.axhline(y=80, color='orange', linestyle='--', alpha=0.5, label='80% threshold')
    ax4.legend(loc='upper right', fontsize=8)
    
    # Plot 5: Absolute Memory Usage (MIDDLE MIDDLE)
    ax5 = fig.add_subplot(gs[1, 1])
    ax5.plot(df['Elapsed_sec'], df['System_Used_MB'], 'r-', linewidth=2, label='Used')
    ax5.plot(df['Elapsed_sec'], df['System_Available_MB'], 'm-', linewidth=2, label='Available')
    ax5.fill_between(df['Elapsed_sec'], df['System_Used_MB'], alpha=0.2, color='red')
    ax5.set_xlabel('Time (seconds)', fontsize=10)
    ax5.set_ylabel('Memory (MB)', fontsize=10)
    ax5.set_title('System Memory Usage (Absolute)', fontsize=12, fontweight='bold')
    ax5.grid(True, alpha=0.3)
    ax5.legend(loc='upper right', fontsize=9)
    
    # Plot 6: Process Memory (MIDDLE RIGHT)
    ax6 = fig.add_subplot(gs[1, 2])
    ax6.plot(df['Elapsed_sec'], df['Process_RSS_MB'], 'c-', linewidth=2)
    ax6.fill_between(df['Elapsed_sec'], df['Process_RSS_MB'], alpha=0.3, color='cyan')
    ax6.set_xlabel('Time (seconds)', fontsize=10)
    ax6.set_ylabel('Memory (MB)', fontsize=10)
    ax6.set_title('OP-TEE Process Memory (RSS)', fontsize=12, fontweight='bold')
    ax6.grid(True, alpha=0.3)
    
    # Plot 7: Context Switch Rate (BOTTOM LEFT)
    ax7 = fig.add_subplot(gs[2, 0])
    df['CtxSwitch_Rate'] = df['CtxSwitches'].diff() / df['Elapsed_ms'].diff() * 1000
    df_clean = df[df['CtxSwitch_Rate'].notna() & (df['CtxSwitch_Rate'] != float('inf'))]
    ax7.plot(df_clean['Elapsed_sec'], df_clean['CtxSwitch_Rate'], 'orange', linewidth=1.5)
    ax7.set_xlabel('Time (seconds)', fontsize=10)
    ax7.set_ylabel('Context Switches/sec', fontsize=10)
    ax7.set_title('Context Switch Rate', fontsize=12, fontweight='bold')
    ax7.grid(True, alpha=0.3)
    
    # Plot 8: Resource Utilization Heatmap (BOTTOM MIDDLE)
    ax8 = fig.add_subplot(gs[2, 1])
    # Create time bins
    time_bins = 20
    bin_edges = pd.cut(df['Elapsed_sec'], bins=time_bins)
    cpu_bins = df.groupby(bin_edges)['System_CPU_Percent'].mean()
    mem_bins = df.groupby(bin_edges)['System_Used_Percent'].mean()
    
    x = range(len(cpu_bins))
    width = 0.35
    ax8.bar([i - width/2 for i in x], cpu_bins, width, label='CPU %', alpha=0.8, color='blue')
    ax8.bar([i + width/2 for i in x], mem_bins, width, label='Memory %', alpha=0.8, color='red')
    ax8.set_xlabel('Time Bins', fontsize=10)
    ax8.set_ylabel('Utilization (%)', fontsize=10)
    ax8.set_title('Resource Utilization Over Time Bins', fontsize=12, fontweight='bold')
    ax8.legend(fontsize=9)
    ax8.grid(True, alpha=0.3, axis='y')
    
    # Plot 9: Summary Statistics (BOTTOM RIGHT)
    ax9 = fig.add_subplot(gs[2, 2])
    ax9.axis('off')
    
    # Calculate comprehensive statistics
    total_mem_mb = df['System_Total_MB'].iloc[0]
    
    stats_text = f"""
    ═══════════════════════════════════════
         PERFORMANCE SUMMARY
    ═══════════════════════════════════════
    
    Duration: {df['Elapsed_sec'].max():.2f} seconds
    
    ─── SYSTEM CPU ───────────────────────
    Average:  {df['System_CPU_Percent'].mean():.1f}%
    Peak:     {df['System_CPU_Percent'].max():.1f}%
    Minimum:  {df['System_CPU_Percent'].min():.1f}%
    
    ─── PROCESS CPU ──────────────────────
    Average:  {df['Process_CPU_Percent'].mean():.1f}%
    Peak:     {df['Process_CPU_Percent'].max():.1f}%
    
    ─── SYSTEM MEMORY ────────────────────
    Total:    {total_mem_mb:.0f} MB
    Avg Used: {df['System_Used_Percent'].mean():.1f}%
              ({df['System_Used_MB'].mean():.0f} MB)
    Peak:     {df['System_Used_Percent'].max():.1f}%
              ({df['System_Used_MB'].max():.0f} MB)
    
    ─── PROCESS MEMORY ───────────────────
    Average:  {df['Process_RSS_MB'].mean():.2f} MB
    Peak:     {df['Process_RSS_MB'].max():.2f} MB
    
    ─── CONTEXT SWITCHES ─────────────────
    Total:    {df['CtxSwitches'].max() - df['CtxSwitches'].min():.0f}
    Avg Rate: {df_clean['CtxSwitch_Rate'].mean():.0f}/sec
    Peak:     {df_clean['CtxSwitch_Rate'].max():.0f}/sec
    
    ═══════════════════════════════════════
    """
    
    ax9.text(0.05, 0.5, stats_text, fontsize=9, family='monospace',
             verticalalignment='center',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))
    
    plt.tight_layout()
    
    # Save the figure
    output_file = csv_file.replace('.csv', '_system_graphs.png')
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"\n✓ Graphs saved to: {output_file}")
    
    # Print key insights
    print("\n" + "="*60)
    print("KEY INSIGHTS")
    print("="*60)
    print(f"System CPU: Avg {df['System_CPU_Percent'].mean():.1f}%, Peak {df['System_CPU_Percent'].max():.1f}%")
    print(f"Process CPU: Avg {df['Process_CPU_Percent'].mean():.1f}%, Peak {df['Process_CPU_Percent'].max():.1f}%")
    print(f"System Memory: Avg {df['System_Used_Percent'].mean():.1f}%, Peak {df['System_Used_Percent'].max():.1f}%")
    print(f"Process Memory: Avg {df['Process_RSS_MB'].mean():.2f}MB, Peak {df['Process_RSS_MB'].max():.2f}MB")
    print("="*60)
    
    plt.show()

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <performance_csv_file>")
        print("\nExample:")
        print(f"  {sys.argv[0]} optee_performance_20241013_143022.csv")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    if not os.path.exists(csv_file):
        print(f"Error: File not found: {csv_file}")
        sys.exit(1)
    
    print("="*60)
    print("OP-TEE System-Level Performance Visualizer")
    print("="*60)
    plot_performance_data(csv_file)

if __name__ == "__main__":
    main()
