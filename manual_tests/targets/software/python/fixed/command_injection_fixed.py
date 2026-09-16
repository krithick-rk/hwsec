import sys
import subprocess
import ipaddress

def process_file(user_input):
    # Strict validation of IP input
    try:
        ip = ipaddress.ip_address(user_input)
    except ValueError:
        raise ValueError("Invalid IP address provided")

    # Structured argument list without shell execution
    res = subprocess.run(["ping", "-c", "1", str(ip)], shell=False, capture_output=True, text=True)
    return res.stdout

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(process_file(target))
