import sys
import subprocess

def process_file(user_input):
    # Unsanitized command construction
    cmd = f"ping -c 1 {user_input}"
    print(f"Executing: {cmd}")
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res.stdout

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(process_file(target))
