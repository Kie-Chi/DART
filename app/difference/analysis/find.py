import json
import glob
import os
import csv
from pathlib import Path

# Configure data directory
DATA_DIR = "./fuzzer_output/analyze"
OUTPUT_CSV = "error_report.csv"

def find_internal_errors(data_dir):
    files = glob.glob(os.path.join(data_dir, "analyze_*.json"))
    files.sort()  # Sort by filename for easier timeline viewing

    print(f"Scanning {len(files)} files to find INTERNAL_ERROR...")

    error_list = []

    for file_path in files:
        try:
            filename = Path(file_path).stem
            # Extract iteration ID (timestamp)
            try:
                iteration_id = filename.split('_')[1]
            except IndexError:
                iteration_id = filename

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content: continue
                data = json.loads(content)

            # Check each resolver result in this file
            for resolver_key, result in data.items():
                resolver_name = resolver_key.replace("resolver:", "")

                # Core logic: status is error
                if result.get("status") == "error":
                    error_msg = result.get("message", "No error message provided")

                    # Record error details
                    error_info = {
                        "iteration_id": iteration_id,  # Key: corresponds to the Fuzzer iteration
                        "file_path": file_path,
                        "resolver": resolver_name,
                        "error_message": error_msg
                    }
                    error_list.append(error_info)

                    # Print to console for quick review
                    print(f"[Error Found] Iteration: {iteration_id} | Resolver: {resolver_name}")
                    print(f"  -> Reason: {error_msg}")
                    print("-" * 50)

        except json.JSONDecodeError:
            print(f"Skipping invalid JSON file: {file_path}")
        except Exception as e:
            print(f"Warning: Error reading {file_path}: {e}")

    return error_list

def save_to_csv(error_list, output_file):
    if not error_list:
        print("\nCongratulations! No INTERNAL_ERROR found.")
        return

    headers = ["iteration_id", "resolver", "error_message", "file_path"]

    try:
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(error_list)
        print(f"\nScan complete. Found {len(error_list)} errors.")
        print(f"Detailed report saved to: {output_file}")
        print("Tip: You can use 'iteration_id' to find the corresponding Mutation Payload in the Fuzzer send log.")
    except Exception as e:
        print(f"Failed to save CSV: {e}")

if __name__ == "__main__":
    if not os.path.exists(DATA_DIR):
        print(f"Error: Directory {DATA_DIR} does not exist.")
    else:
        errors = find_internal_errors(DATA_DIR)
        save_to_csv(errors, OUTPUT_CSV)