import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

# --- Configuration ---
csv_file = "40MB-3MB-with-halfms.csv"
base_name = os.path.splitext(os.path.basename(csv_file))[0]
output_dir = "."

# -------------------------------
#  Load data
# -------------------------------
try:
    df = pd.read_csv(csv_file)
    print(f"Successfully loaded '{csv_file}'.")
except FileNotFoundError:
    print(f"Error: File '{csv_file}' not found.")
    exit()
except Exception as e:
    print(f"Error loading CSV: {e}")
    exit()

# -------------------------------
#  Filter data to the first 200ms
# -------------------------------
df_200ms = df[df['Elapsed_ms'] <= 200].copy()
if df_200ms.empty:
    print("No data found in the first 200ms.")
    exit()
else:
    print(f"\nFiltered data to first 200ms. {len(df_200ms)} rows remaining.")

# -------------------------------
#  Plot: System CPU Usage (0-200ms)
# -------------------------------
try:
    # Set plot style
    sns.set_theme(style="whitegrid", font_scale=1.1)
    
    # Define ticks for every 5ms
    x_ticks = np.arange(0, 201, 5) 
    
    plt.figure(figsize=(14, 6))
    
    # Use 'steps-post' to clearly show the 1ms samples
    sns.lineplot(data=df_200ms, x='Elapsed_ms', y='System_CPU_Percent', 
                 color='tab:blue', linewidth=2.0, label='System_CPU_Percent',
                 drawstyle='steps-post') 
    
    plt.title('Total System CPU Usage (First 200ms) - 1ms Interval', fontsize=16, weight='bold')
    plt.xlabel('Elapsed Time (ms)')
    plt.ylabel('System CPU Usage (%)')
    
    # --- Set plot limits and ticks ---
    plt.xlim(0, 200)
    plt.yticks(np.arange(0, 101, 20))
    # Apply the 5ms interval ticks
    plt.xticks(x_ticks, rotation=90, fontsize=8) 
    
    # Add a light grid for the x-axis ticks
    plt.grid(which='major', axis='x', linestyle='--', alpha=0.7)
    
    plt.legend(loc='upper right')
    plt.tight_layout()
    
    # --- Save the plot ---
    plot_path = os.path.join(output_dir, f"{base_name}_system_cpu_200ms.png")
    plt.savefig(plot_path, dpi=300)
    
    print(f"✅ Generated System CPU plot (0-200ms): {plot_path}")

except Exception as e:
    print(f"Error generating plot: {e}")
