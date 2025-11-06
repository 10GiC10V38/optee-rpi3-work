import re
import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter
import matplotlib.ticker as ticker
import sys

def parse_data(log_file):
    """
    Parses the log file to extract file sizes (bytes) and 
    pure hash compute times (microseconds).
    """
    data_points = []
    current_size = None

    try:
        with open(log_file, 'r') as f:
            for line in f:
                # Find the file size line
                size_match = re.search(r'File size: (\d+) bytes', line)
                if size_match:
                    current_size = int(size_match.group(1))

                # Find the time line for the current file size
                time_match = re.search(r'Pure Hash Compute Time: (\d+) us', line)
                if time_match and current_size is not None:
                    time_us = int(time_match.group(1))
                    data_points.append((current_size, time_us))
                    # Reset current_size to ensure we get a new pair
                    current_size = None

    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        print(f"Please place the script in the same directory as '{log_file}'")
        sys.exit(1)
        
    # Sort by file size just in case
    data_points.sort(key=lambda x: x[0])
    return data_points

def plot_hash_performance(data_points, output_filename="hash_performance_plot_linear.png"):
    """
    Generates and saves a high-quality, academic-style plot.
    """
    if not data_points:
        print("Error: No data points were parsed. Cannot generate plot.")
        return

    # Unzip data into separate lists
    file_sizes_bytes = [d[0] for d in data_points]
    times_us = [d[1] for d in data_points]

    # Convert file size to KB
    file_sizes_kb = [s / 1024 for s in file_sizes_bytes]

    # --- Create the Plot ---
    
    # Set a professional style
    plt.style.use('seaborn-v0_8-whitegrid')
    
    # Create a figure
    plt.figure(figsize=(10, 6))

    # Plot the data: line, markers, and a label
    plt.plot(file_sizes_kb, times_us, marker='o', linestyle='-', 
             color='b', label='SHA-256 (Single-shot in TEE)')

    # --- NEW: Use LINEAR scales for both axes ---
    # plt.xscale('log', base=2)  <-- Removed
    # plt.yscale('log', base=10) <-- Removed
    
    # --- Customize Labels, Title, and Ticks ---
    
    # Title and axis labels
    plt.title('SHA-256 Hash Computation Performance (2KB-10KB)', fontsize=16, fontweight='bold')
    plt.xlabel('File Size (KB)', fontsize=12)
    plt.ylabel('Pure Compute Time (µs)', fontsize=12) # Changed to microseconds

    # Set explicit x-axis ticks to match our data points
    plt.xticks(file_sizes_kb, [f'{int(s)}' for s in file_sizes_kb])
    
    # Ensure y-axis starts from 0 (or slightly below min) for a standard graph
    min_time = min(times_us)
    max_time = max(times_us)
    plt.ylim(0, max_time * 1.1) # Start y-axis at 0

    # Add a grid and legend
    plt.grid(True, which="both", linestyle='--', linewidth=0.5)
    plt.legend(fontsize=12)

    # Adjust layout
    plt.tight_layout()

    # Save the plot
    plt.savefig(output_filename, dpi=300)
    
    print(f"Successfully generated plot and saved as '{output_filename}'")
    
    # Optionally display the plot
    # plt.show()

# --- Main execution ---
if __name__ == "__main__":
    # --- NEW: Point to the new log file ---
    LOG_FILE = 'linear_timings.txt'
    parsed_data = parse_data(LOG_FILE)
    plot_hash_performance(parsed_data, "hash_performance_plot_linear.png")
