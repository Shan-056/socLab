import email, re, sys, hashlib
from email import policy

m = email.message_from_binary_file(open(sys.argv[1], "rb"), policy=policy.default)
for h in ("From", "Return-Path", "Reply-To", "Subject", "Date", "Message-ID",
          "Authentication-Results", "Received-SPF"):
    print(f"{h}: {m[h]}")

print("\n--- Received (top = last hop, bottom = first) ---")
for r in m.get_all("Received", []):
    print(" ", " ".join(r.split())[:220])

n = 0
for part in m.walk():
    ct = part.get_content_type()
    if ct in ("text/plain", "text/html"):
        body = part.get_content()
        print(f"\n--- {ct} ---")
        if ct == "text/plain":
            print(body[:1500])
            print("URLs:", sorted(set(re.findall(r'https?://[^\s<>"]+', body))))
        else:
            for href, text in re.findall(
                    r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', body, re.S | re.I):
                print("LINK:", re.sub(r"\s+", " ", re.sub("<[^>]+>", "", text)).strip()[:60],
                      "->", href)
    elif part.get_filename():
        n += 1
        data = part.get_payload(decode=True) or b""
        open(f"att_{n}.bin", "wb").write(data)   # .bin so it can't be opened by accident
        print(f"\nATTACHMENT {n}: {part.get_filename()} ({ct}, {len(data)} bytes)")
        print("SHA-256:", hashlib.sha256(data).hexdigest())