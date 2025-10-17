import sys, re, unicodedata
from typing import Optional

def _ror(n: int, r: int, width: int = 32) -> int:
    r %= width
    mask = (1 << width) - 1
    return ((n >> r) | ((n << (width - r)) & mask)) & mask

def sha256(message: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("sha256() expects bytes")
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    ml = len(message) * 8
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += ml.to_bytes(8, 'big')
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = [0] * 64
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:j*4+4], 'big')
        for j in range(16, 64):
            s0 = _ror(w[j-15], 7) ^ _ror(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = _ror(w[j-2], 17) ^ _ror(w[j-2], 19) ^ (w[j-2] >> 10)
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xffffffff
        a, b, c, d, e, f, g, htemp = h
        for j in range(64):
            S1 = _ror(e, 6) ^ _ror(e, 11) ^ _ror(e, 25)
            ch = (e & f) ^ ((~e & 0xffffffff) & g)
            temp1 = (htemp + S1 + ch + k[j] + w[j]) & 0xffffffff
            S0 = _ror(a, 2) ^ _ror(a, 13) ^ _ror(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff
            htemp = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff
        h = [
            (h[0] + a) & 0xffffffff,
            (h[1] + b) & 0xffffffff,
            (h[2] + c) & 0xffffffff,
            (h[3] + d) & 0xffffffff,
            (h[4] + e) & 0xffffffff,
            (h[5] + f) & 0xffffffff,
            (h[6] + g) & 0xffffffff,
            (h[7] + htemp) & 0xffffffff
        ]
    return b''.join(x.to_bytes(4, 'big') for x in h)

def sha256_hex(message: bytes) -> str:
    return sha256(message).hex()

def normalize_text(s: str) -> str:
    s = unicodedata.normalize('NFKC', s)
    s = s.replace('\r\n', '\n').replace('\r', '\n')
    s = re.sub(r'\s+', ' ', s)
    return s.strip()

def load_mark_text_from_file(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def try_fetch_mark_text_from_url(url: str) -> Optional[str]:
    try:
        import requests
        from bs4 import BeautifulSoup
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'lxml')
        main = soup.find('main') or soup.find('div', id='content') or soup.find('div', {'class': 'content'}) or soup.body
        text = main.get_text(separator='\n', strip=True)
        return text
    except Exception as e:
        print(f"[warn] fetch failed: {e}")
        return None

HELP = """
Usage:
  python3 sha256_mark.py --file mark_rsv.txt
  python3 sha256_mark.py --url "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892"
"""

def main(argv):
    if len(argv) < 2 or argv[1] not in ("--file", "--url"):
        print(HELP.strip())
        sys.exit(1)
    if argv[1] == "--file":
        if len(argv) < 3:
            print("Error: missing path. Example: python3 sha256_mark.py --file mark_rsv.txt")
            sys.exit(1)
        raw = load_mark_text_from_file(argv[2])
    else:
        url = argv[2] if len(argv) >= 3 else "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892"
        fetched = try_fetch_mark_text_from_url(url)
        if not fetched:
            print("Error: failed to fetch. Copy the page text to 'mark_rsv.txt' and run with --file.")
            sys.exit(2)
        raw = fetched
    clean = normalize_text(raw)
    b = clean.encode('utf-8')
    t0 = sha256_hex(b"")
    t1 = sha256_hex(b"abc")
    assert t0 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Empty string test failed"
    assert t1 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "'abc' test failed"
    print("SHA-256 implementation tests passed.")
    print("Raw length (chars):", len(raw))
    print("Normalized length (bytes, UTF-8):", len(b))
    print("SHA-256(Book of Mark) =", sha256_hex(b))

if __name__ == "__main__":
    main(sys.argv)
