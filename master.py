import subprocess

def run_scripts():
    # Run the scanning script
    print("Starting the scanning process...")
    result_scan = subprocess.run(['python', 'scripts/tshark-capture.py'], text=True)
    print("Scanning complete.")

    # Check if the scan was successful
    if result_scan.returncode == 0:
        print("Starting the analysis...")
        # Run the analysis script
        result_analysis = subprocess.run(['python', 'scripts/analyze-capture-results.py'], text=True)
        print("Analysis complete.")
    else:
        print("Scanning script encountered an error.")

if __name__ == "__main__":
    run_scripts()
