# hash_calc.py
import hashlib
import sys

def compute_hash(path, algorithm):
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python hash_calc.py <path-to-file>")
        sys.exit(1)
    p = sys.argv[1]
    print("MD5:   ", compute_hash(p, "md5"))
    print("SHA1:  ", compute_hash(p, "sha1"))
    print("SHA256:", compute_hash(p, "sha256"))
