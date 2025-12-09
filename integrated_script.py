# integrated_script.py
import hashlib, pefile, re, yara, sys

def compute_hashes(path):
    algos = ["md5", "sha1", "sha256"]
    output = {}
    for a in algos:
        h = hashlib.new(a)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        output[a] = h.hexdigest()
    return output

def extract_strings(path, min_len=4):
    with open(path, "rb") as f:
        data = f.read()
    return re.findall(rb"[ -~]{%d,}" % min_len, data)

def find_urls_ips(text):
    import re
    urls = re.findall(r"https?://[^\s\"']+", text)
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    return urls, ips

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python integrated_script.py <path-to-file>")
        sys.exit(1)
    sample = sys.argv[1]

    print("Hashes:", compute_hashes(sample))

    s = extract_strings(sample)[:100]
    print("\nStrings (first 100):")
    for x in s:
        try:
            print(x.decode(errors="ignore"))
        except:
            pass

    print("\nImports:")
    try:
        pe = pefile.PE(sample)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(entry.dll.decode(errors='ignore'))
        else:
            print("No imports found.")
    except Exception as e:
        print("pefile error:", e)

    print("\nIOCs:")
    decoded = open(sample, "rb").read().decode(errors="ignore")
    urls, ips = find_urls_ips(decoded)
    print("URLs:", urls)
    print("IPs:", ips)

    print("\nYARA:")
    rule = yara.compile(source='''
rule Simple { strings: $s = "http" condition: $s }
''')
    print(rule.match(sample))
