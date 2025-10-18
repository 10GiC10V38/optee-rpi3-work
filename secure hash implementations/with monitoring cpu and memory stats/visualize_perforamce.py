import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec  # Import GridSpec for better layout control
import os
import sys

def visualize_performance(csv_file, report_text):
    """
    Generates a 2x2 grid of performance graphs with a dedicated text report area below.
    """
    try:
        df = pd.read_csv(csv_file)
        if df.empty:
            print(f"Warning: CSV file '{csv_file}' is empty. Skipping visualization.")
            return
    except Exception as e:
        print(f"Error reading or processing CSV file '{csv_file}': {e}")
        return

    # --- CHANGE: Increased figure height to comfortably fit the text box ---
    fig = plt.figure(figsize=(20, 16))
    fig.suptitle(f'System Performance Analysis: {os.path.basename(csv_file)}', fontsize=20, weight='bold')

    # --- CHANGE: Use GridSpec to define a structured layout ---
    # This creates a grid: 3 rows, 2 columns. The plots will be in the first two rows.
    # The last row is reserved for the text report.
    gs = gridspec.GridSpec(3, 2, figure=fig, height_ratios=[1, 1, 0.6])

    # Create axes for the four plots in the upper grid
    ax1 = fig.add_subplot(gs[0, 0])  # Top-left
    ax2 = fig.add_subplot(gs[0, 1])  # Top-right
    ax3 = fig.add_subplot(gs[1, 0])  # Middle-left
    ax4 = fig.add_subplot(gs[1, 1])  # Middle-right

    # Create a single, wide axis in the bottom row for the text
    ax_text = fig.add_subplot(gs[2, :])

    # --- Plotting code remains the same, but uses specific axes (ax1, ax2, etc.) ---

    # Plot 1: CPU Utilization
    ax1.plot(df['Elapsed_ms'], df['System_CPU_Percent'], label='System CPU %', color='red', linewidth=2)
    ax1.plot(df['Elapsed_ms'], df['Process_CPU_Percent'], label='Process CPU %', color='blue', linestyle='--')
    ax1.set_title('CPU Utilization Over Time', fontsize=14, weight='bold')
    ax1.set_xlabel('Time (ms)')
    ax1.set_ylabel('CPU Usage (%)')
    ax1.legend()
    ax1.grid(True, linestyle=':', alpha=0.6)

    # Plot 2: Process Memory Usage
    ax2.plot(df['Elapsed_ms'], df['Process_RSS_KB'] / 1024, label='Process RSS (MB)', color='purple')
    ax2.plot(df['Elapsed_ms'], df['Process_VmSize_KB'] / 1024, label='Process VmSize (MB)', color='orange', linestyle='--')
    ax2.set_title('Process Memory Usage Over Time', fontsize=14, weight='bold')
    ax2.set_xlabel('Time (ms)')
    ax2.set_ylabel('Memory (MB)')
    ax2.legend()
    ax2.grid(True, linestyle=':', alpha=0.6)

    # Plot 3: System Memory Usage
    ax3.plot(df['Elapsed_ms'], df['System_Used_Percent'], label='System Used %', color='green')
    ax3.plot(df['Elapsed_ms'], df['System_Available_Percent'], label='System Available %', color='teal', linestyle='--')
    ax3.set_title('System Memory Usage (%) Over Time', fontsize=14, weight='bold')
    ax3.set_xlabel('Time (ms)')
    ax3.set_ylabel('Memory Usage (%)')
    ax3.legend()
    ax3.grid(True, linestyle=':', alpha=0.6)

    # Plot 4: Context Switches (showing rate of change)
    ctx_switches_delta = df['CtxSwitches'].diff().fillna(0)
    ax4.plot(df['Elapsed_ms'], ctx_switches_delta, label='Context Switches (per sample)', color='brown')
    ax4.set_title('Context Switches Rate Over Time', fontsize=14, weight='bold')
    ax4.set_xlabel('Time (ms)')
    ax4.set_ylabel('Number of Switches')
    ax4.legend()
    ax4.grid(True, linestyle=':', alpha=0.6)

    # --- CHANGE: Place the text inside the dedicated text axis ---
    ax_text.axis('off')  # Hide the axes ticks and lines
    ax_text.text(0.01, 0.95, report_text,
                 ha='left',
                 va='top',
                 fontsize=14,
                 bbox={"facecolor": "#f0f0f0", "edgecolor": "black", "pad": 10},
                 family='monospace') # Use a monospace font for better text alignment

    # Adjust layout to prevent titles and labels from overlapping
    fig.tight_layout(rect=[0, 0, 1, 0.96])

    # Save the figure
    output_filename = f"{os.path.splitext(csv_file)[0]}_system_graphs.jpg"
    plt.savefig(output_filename, dpi=150, bbox_inches='tight')
    plt.close()

    print(f"Generated performance graph: {output_filename}")


def get_summary_report(csv_file):
    """
    Generates a text summary from the performance CSV file.
    """
    try:
        df = pd.read_csv(csv_file)
        if df.empty:
            return "No data available to generate a report."
    except Exception:
        return f"Could not process {csv_file} for summary."

    report = (
        f"PERFORMANCE SUMMARY REPORT\n"
        f"--------------------------\n"
        f"File: {os.path.basename(csv_file)}\n"
        f"Duration: {df['Elapsed_ms'].max() / 1000:.2f} seconds\n\n"
        f"CPU USAGE:\n"
        f"  - Process CPU (Avg): {df['Process_CPU_Percent'].mean():.2f} %\n"
        f"  - Process CPU (Max): {df['Process_CPU_Percent'].max():.2f} %\n"
        f"  - System CPU (Avg):  {df['System_CPU_Percent'].mean():.2f} %\n"
        f"  - System CPU (Max):  {df['System_CPU_Percent'].max():.2f} %\n\n"
        f"PROCESS MEMORY:\n"
        f"  - RSS Memory (Avg):  {df['Process_RSS_KB'].mean() / 1024:.2f} MB\n"
        f"  - RSS Memory (Peak): {df['Process_RSS_KB'].max() / 1024:.2f} MB\n\n"
        f"CONTEXT SWITCHES:\n"
        f"  - Total Switches: {df['CtxSwitches'].max() - df['CtxSwitches'].min()}\n"
    )
    return report


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python visualize_performance.py <path_to_csv_file1> [<path_to_csv_file2> ...]")
        sys.exit(1)

    csv_files = sys.argv[1:]
    for csv_file in csv_files:
        if os.path.exists(csv_file):
            print(f"\nProcessing {csv_file}...")
            summary_report = get_summary_report(csv_file)
            print(summary_report)
            visualize_performance(csv_file, summary_report)
        else:
            print(f"Error: File not found at '{csv_file}'")
