#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os

# -------------------------------
#  Argument handling
# -------------------------------
if len(sys.argv) < 2:
    print("Usage: python3 analyze_process_usage.py <input_file.csv>")
    sys.exit(1)

csv_file = sys.argv[1]

if not os.path.exists(csv_file):
    print(f"Error: File '{csv_file}' not found.")
    sys.exit(1)

# -------------------------------
#  Load data
# -------------------------------
df = pd.read_csv(csv_file)
sns.set(style="whitegrid", font_scale=1.2)

base_name = os.path.splitext(os.path.basename(csv_file))[0]
output_dir = os.path.dirname(csv_file) or "."

# -------------------------------
#  1. Process CPU Usage Plot
# -------------------------------
plt.figure(figsize=(12, 5))
sns.lineplot(x="Elapsed_ms", y="Process_CPU_Percent", data=df, color="tab:blue", linewidth=2)
plt.title("Process CPU Usage Over Time", fontsize=14, weight='bold')
plt.xlabel("Elapsed Time (ms)")
plt.ylabel("CPU Usage (%)")
plt.tight_layout()

cpu_plot_path = os.path.join(output_dir, f"{base_name}_process_cpu.png")
plt.savefig(cpu_plot_path, dpi=300)
plt.close()

# -------------------------------
#  2. Process Memory Usage Plot
# -------------------------------
plt.figure(figsize=(12, 5))
sns.lineplot(x="Elapsed_ms", y="Process_RSS_KB", data=df, label="RSS (KB)", linewidth=2)
sns.lineplot(x="Elapsed_ms", y="Process_VmSize_KB", data=df, label="VmSize (KB)", linewidth=2)
plt.title("Process Memory Usage Over Time", fontsize=14, weight='bold')
plt.xlabel("Elapsed Time (ms)")
plt.ylabel("Memory (KB)")
plt.legend()
plt.tight_layout()

mem_plot_path = os.path.join(output_dir, f"{base_name}_process_memory.png")
plt.savefig(mem_plot_path, dpi=300)
plt.close()

# -------------------------------
#  Done
# -------------------------------
print(f"✅ Process CPU usage plot saved as: {cpu_plot_path}")
print(f"✅ Process memory usage plot saved as: {mem_plot_path}")
print("Analysis complete.")

