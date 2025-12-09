# strings_extract.py
import re
import sys

def extract_strings(path, min_len=4):
    with open(path, "rb") as f:
        data = f.read()
    pattern = rb"[ -~]{" + str(min_len).encode() + rb",}"
    return re.findall(pattern, data)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python strings_extract.py <path-to-file>")
        sys.exit(1)
    strings = extract_strings(sys.argv[1], min_len=4)
    for s in strings[:200]:
        try:
            print(s.decode('ascii', errors='ignore'))
        except Exception:
            pass
