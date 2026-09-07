import os
import sys

def execute_user_command(user_input):
    print("Executing system command...")
    # Deliberate CWE-78: Command injection vulnerability
    os.system("echo Processing: " + user_input)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        execute_user_command(sys.argv[1])
