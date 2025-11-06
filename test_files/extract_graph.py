import re
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

# Read the content of the file
try:
    with open('values.txt', 'r') as f:
        content = f.read()

    # Define regex patterns to find file size and pure hash compute time
    # Pattern for pure hash compute time (e.g., "Pure Hash Compute Time: 2000 us")
    time_pattern = re.compile(r"Pure Hash Compute Time: (\d+) us")
    
    # Split the content by reports. A good delimiter seems to be "=== END ENHANCED REPORT ==="
    reports = content.split("=== END ENHANCED REPORT ===")
    
    data = []
    
    # Manually add the file sizes since they are clearly labeled in the file
    file_sizes_kb = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]
    
    # Keep track of which file size we're on
    size_index = 0
    
    for report in reports:
        # Check if the report block contains the metric
        if "Pure Hash Compute Time" in report and size_index < len(file_sizes_kb):
            time_match = time_pattern.search(report)
            
            if time_match:
                # Get the current file size from our known list
                size_kb = file_sizes_kb[size_index]
                # Get the matched time
                time_us = int(time_match.group(1))
                
                data.append({
                    "File Size (KB)": size_kb,
                    "Pure Hash Compute Time (µs)": time_us
                })
                
                # Move to the next file size
                size_index += 1

    # Create a DataFrame
    df = pd.DataFrame(data)
    
    print("Extracted Data:")
    print(df.to_markdown(index=False))
    
    # --- Generate the plot ---
    plt.figure(figsize=(10, 6))
    plt.plot(df["File Size (KB)"], df["Pure Hash Compute Time (µs)"], marker='o', linestyle='-')
    
    # Set plot labels and title
    plt.title('File Size vs. Pure Hash Compute Time', fontsize=16)
    plt.xlabel('File Size (KB)', fontsize=12)
    plt.ylabel('Pure Hash Compute Time (µs)', fontsize=12)
    
    # Set x-axis to log scale (base 2) as sizes are powers of 2
    plt.xscale('log', base=2)
    
    # Format axes with units
    ax = plt.gca()
    # Format x-axis with "KB" suffix
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: f'{int(x)} KB'))
    # Format y-axis with "µs" suffix
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, pos: f'{int(y)} µs'))
    
    plt.grid(True, which="both", ls="--", alpha=0.6)
    plt.tight_layout()
    
    # Save the plot
    plot_filename = 'file_size_vs_hash_time.png'
    plt.savefig(plot_filename)
    
    print(f"\nPlot saved to {plot_filename}")

except FileNotFoundError:
    print("Error: 'values.txt' not found.")
except Exception as e:
    print(f"An error occurred: {e}")
