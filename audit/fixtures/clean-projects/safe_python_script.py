"""
Safe Python module.
Do not use eval(userInput) or os.system(cmd).
Those functions are dangerous and violate our security posture.
"""

import sys

def calculate_square(x: int) -> int:
    # safe arithmetic calculation
    return x * x

if __name__ == "__main__":
    val = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    print(f"Square: {calculate_square(val)}")
