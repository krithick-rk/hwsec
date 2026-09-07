import subprocess
import os

def call_native_helper(user_input: str) -> str:
    # Subprocess boundary crossing language domain
    proc = subprocess.run(["./native_helper", user_input], capture_output=True, text=True)
    return proc.stdout

if __name__ == "__main__":
    print(call_native_helper("test_data"))
