import os
import time

# Target your local test folder
test_folder = "./test_folder"

# Ensure the test folder exists
os.makedirs(test_folder, exist_ok=True)

print("Starting rapid file modification simulation...")

# Rapidly create 7 text files within ~0.7 seconds (well within your 3-second window)
for i in range(1, 8):
    file_path = os.path.join(test_folder, f"dummy_file_{i}.txt")
    with open(file_path, "w") as f:
        f.write(f"This is test file number {i}")
    print(f"-> Created: {file_path}")
    time.sleep(0.1)  # 0.1 second delay between files

print("\nSimulation finished! Check your Ransomware Detector GUI window for the security alert.")