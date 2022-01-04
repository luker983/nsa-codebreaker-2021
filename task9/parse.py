#!/usr/bin/env python3

import nacl.secret
import hashlib
import struct

# define values for commands, parameters, and other magic numbers
MAGIC_START = b'\x18\x15\xe9\xd3' 
MAGIC_END = b'\xef\x5a\x80\xcb'
RESPONSE_CODE_LENGTH = 4

# command names from Ghidra
# missing commands 1, 3, 4, and 5
commands = {
    1: "COMMAND_ONE",
    2: "COMMAND_INIT",
    3: "COMMAND_THREE",
    4: "COMMAND_FOUR",
    5: "COMMAND_FIVE",
    6: "COMMAND_UPLOAD",
    7: "COMMAND_FIN",
}

# parameters from Ghidra
params = {
    0x1100: "PARAM_CMD",
    0x1108: "PARAM_UUID",
    0x1114: "PARAM_DIRNAME",
    0x111c: "PARAM_FILENAME",
    0x1120: "PARAM_CONTENTS",
    0x1124: "PARAM_MORE",
    0x1128: "PARAM_CODE",
}

# cracked fingerprints
fingerprints = [
    "sayre+1.6.7.9+1615897640",
    "root+1.2.2.0+1615897678",
    "chickie+2.7.5.7+1615897729",
]

def keygen(fp):
    h = hashlib.sha256()
    h.update(fp.encode())
    return h.digest()

def decrypt(ciphertext, nonce, key):
    box = nacl.secret.SecretBox(key)
    return box.decrypt(nonce + ciphertext)

# algorithm can be derived from lengthHeader() in Ghidra
def get_length(header):
    s1, s2 = struct.unpack('!HH', header)
    return (s1 + s2) % 0x10000

# load each session from file
messages = []
for u in ['sayre', 'root', 'chickie']:
    with open(f"sessions/{u}", 'r') as f:
        lines = f.readlines()

    messages.append([bytes.fromhex(line) for line in lines])

# iterate over each session
for i, mlist in enumerate(messages):
    print(f"{'=' * 4} {fingerprints[i]}")

    print(f"Client Public Key: {mlist.pop(0)[:8]}...")
    print(f"Encrypted Fingerprint Message: {mlist.pop(0)[:8]}...")

    # iterate over each message
    for j, m in enumerate(mlist):
        print(f"\t{'=' * 4} Message {j}")

        # parse header, nonce, and ciphertext from encrypted messages
        length_header = m[:4]
        nonce = m[4:28]
        ciphertext = m[28:]

        # decrypt message
        key = keygen(fingerprints[i])
        pt = decrypt(ciphertext, nonce, key)
        
        # decipher length header
        length = get_length(length_header) - (24 + 16)
        print(f"\tLength: {length} ({length_header})")

        # check if message starts with MAGIC_START like it should
        start = pt[:4] == MAGIC_START
        print(f"\tMagic Start? {start} ({pt[:4]})")


        # p is position in message
        p = 4
        # iterate over parameters
        while p <= length:
            # get param
            param = int.from_bytes(pt[p:p + 2], 'big')
            if param in params:
                param_string = params[param]
            else:
                param_string = f"UNKNOWN ({pt[p:p + 2]})"
            p += 2

            # get param length
            param_length = int.from_bytes(pt[p:p + 2], 'big')
            p += 2

            # get param data
            param_data = int.from_bytes(pt[p:p + param_length], 'big')
            if param_data in commands:
                data_string = commands[param_data]
            else:
                data_string = pt[p:p + param_length]
            p += param_length

            print(f"\t\t{param_string} ({param_length}): {data_string}")

            # leave 4 bytes at the end for MAGIC_END
            if p == length - 4:
                break

        # check if message ends with MAGIC_END like it should
        end = pt[-4:] == MAGIC_END
        print(f"\tMagic End?: {end} ({pt[-4:]})")
        print()
