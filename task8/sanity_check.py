#!/usr/bin/env python3

import nacl.secret
import hashlib

# message from GDB session
message = bytes.fromhex('9bed645da57427a83685b817151690b55082e15d10c6c3d4ff9c0f96d1fbd991142b183a0f8f952741d8681d2eb9a3c4052a9d539f4d40870f8b1859bc06e0f61d9f3cef155238abe91eaca4aed2')

# make key by hashing username, version, timestamp
def keygen(username, version, timestamp):
    keystring = f'{username}+{version}+{str(timestamp)}'

    h = hashlib.sha256()
    h.update(f'{username}+{version}+{str(timestamp)}'.encode())

    return h.digest()

# make key from known username, shortened version, and timestamp
key = keygen("unknown", "1.2.2.0", 1630594378)

# parse message
header = message[:4]
nonce = message[4:28]
ciphertext = message[28:]

# make box from key
box = nacl.secret.SecretBox(key)

# try to decrypt
try:
    plaintext = box.decrypt(nonce + ciphertext)
    print("SUCCESS:", plaintext)
except Exception as e:
    print("FAILURE:", e)
