import os
import subprocess
import sys

# run using python3 graph_time_series.py [filename]
# ex. python3 graph_time_series.py stats.txt

def main():
    if (len(sys.argv)) == 2:
        filename = sys.argv[1]
    else:
        print("Argument required for stats filename")
        exit(1)

    # Make directory to store graphs
    try:
        os.mkdir("time_series_graphs")
    except OSError:
        pass
    
    # cd into directory
    os.chdir("time_series_graphs")

    # Run gnuplot script to plot data
    subprocess.run(["gnuplot", "-c", "../plot_time_series.gp", f"../{filename}"])

if __name__ == "__main__":
    main()
