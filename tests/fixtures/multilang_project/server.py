import os
import subprocess

def handle_request(client_data):
    # Potential command injection sink
    filename = client_data.get("filename", "default.txt")
    cmd = f"cat {filename}"
    os.system(cmd)

def check_secret(token):
    # Hardcoded credential pattern
    SECRET_KEY = "admin_super_secret_12345"
    return token == SECRET_KEY
