#!/usr/bin/env python3

import nacl.secret
import uuid
import hashlib

# hash fingerprint
def keygen(fp):
    h = hashlib.sha256()
    h.update(fp.encode())
    return h.digest()

# decrypt message
def decrypt(ciphertext, nonce, key):
    box = nacl.secret.SecretBox(key)
    return box.decrypt(nonce + ciphertext)

# cracked fingerprints
fingerprints = [
    "sayre+1.6.7.9+1615897640",
    "root+1.2.2.0+1615897678",
    "chickie+2.7.5.7+1615897729",
]

# build messages list from PCAP
messages = []
messages.append(bytes.fromhex('6ff290588db134c030a69b63d6319c71d2c35af189cdf55da76eb48ecc9b38ab27f0cf897a2448326cb4b448b716d34ffe7cd9fd215eea31933dce9d50cc042f283d2adc06eb8e0d28c135e621f0'))
messages.append(bytes.fromhex('30ebcf5f20a6d7d06d31c233560d18f13330be17ff8e896c5d61fde2644345cc997c9c627494423b042d545bf6f102a7f10f9b5856c83f49553d1a9cd0661c0d56b435459b046e571f488321f56c'))
messages.append(bytes.fromhex('f5560af46f120876788160addb65aeb3cf365b038567a0302dcb0b377dd70873087e773db76687ce213db432d12c893437bb93a71900c423d707c118695fbd74bd45a713a2f09e1bff87da54e3e9'))

uuids = []
for i, m in enumerate(messages):
    print(f"{'=' * 4} {fingerprints[i]}")
    
    # parse encrypted message
    length = m[:4]
    nonce = m[4:28]
    ciphertext = m[28:]
    key = keygen(fingerprints[i])

    # decrypt message
    p = decrypt(ciphertext, nonce, key)

    # print init message fields
    print(f"MAGIC START: {p[:4]}") 

    # CMD
    print(f"CMD PARAM: {p[4:6]}") 
    print(f"CMD LENGTH: {p[6:8]}") 
    print(f"CMD DATA: {p[8:10]}") 

    # UUID
    print(f"UUID PARAM: {p[10:12]}") 
    print(f"UUID LENGTH: {p[12:14]}") 
    print(f"UUID: {p[14:30]}") 
    
    # parse UUID
    u = uuid.UUID(bytes=p[14:30])
    uuids.append(u)

    print(f"MAGIC END: {p[30:34]}") 
    print()

# print all UUIDs for submission
print(f"{'=' * 4} UUIDs")
for u in uuids: print(u)
