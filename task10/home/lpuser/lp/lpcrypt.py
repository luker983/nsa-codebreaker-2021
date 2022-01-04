import time
import base64
import secrets
import hashlib
import struct
import random
import subprocess
import nacl.utils
import nacl.secret
import nacl.public
from base64 import b64encode, b64decode
from protocol import socket_recv_n
def keyFromFingerprint(fingerprint):
    keystr = f'{fingerprint["username"].lower()}+{fingerprint["version"][:7]}+{fingerprint["timestamp"]}'
    print(keystr)
    digest = hashlib.sha256(keystr.encode()).digest()
    return digest
def deserializeFingerprint(pt):
    print(f'Deserializing Fingerprint {pt}')
    fp = {}
    attributes = pt.split(b',')
    for each in attributes:
        decStr = base64.b64decode(each).decode()
        print(f' -- {decStr}')
        attr, val = decStr.split('=')
        fp[attr] = val
    print("Got fingerprint: ", fp)
    return fp
def serverInitializeCrypt(sock, server_public, server_secret):
    client_public = socket_recv_n(sock, 32)
    print("Received", len(client_public), "bytes")
    client_public = nacl.public.PublicKey(client_public)
    print("Client Public: ", client_public.encode().hex())
    server_public = nacl.public.PublicKey(bytes.fromhex(server_public))
    server_secret = nacl.public.PrivateKey(bytes.fromhex(server_secret))
    length = receiveLength(sock)
    if length == 0 or length <= 24:
        return False
    try:
        message = socket_recv_n(sock, length)
        nonce = message[:24]
        ciphertext = message[24:]
    except Exception as e:
        print(f"Error receiving data!")
        print(f"Exception: {e}")
        return False
    print("Nonce: ", nonce.hex())
    print("Ciphertext: ", ciphertext.hex())
    if ciphertext.startswith(b'\x00' * 16):
        ciphertext = ciphertext[16:]
        print("Ciphertext: ", ciphertext)
    server_box = nacl.public.Box(server_secret, client_public)
    decrypted = server_box.decrypt(ciphertext, nonce)
    fingerprint = deserializeFingerprint(decrypted)
    if fingerprint is None:
        return False
    sessionKey = keyFromFingerprint(fingerprint)
    print("Session Key: ", sessionKey.hex())
    return sessionKey
def encryptMessage(skey, message):
    nonce = nacl.utils.random(24)
    box = nacl.secret.SecretBox(skey)
    ciphertext = box.encrypt(message, nonce)
    lengthHeader = makeLengthHeader(len(ciphertext))
    finalMessage = lengthHeader + ciphertext
    return finalMessage
def decryptMessage(skey, message):
    if len(message) <= 24:
        return None
    nonce = message[:24]
    ciphertext = message[24:]
    if ciphertext.startswith(b'\x00' * 16):
        ciphertext = ciphertext[16:]
        if len(ciphertext) == 0:
            return None
    box = nacl.secret.SecretBox(skey)
    plaintext = box.decrypt(ciphertext, nonce)
    return plaintext
def makeLengthHeader(length):
    size1Bytes = nacl.utils.random(2)
    size1, = struct.unpack('!H', size1Bytes)
    size2 = (length - size1) % 0x10000
    sizes = struct.pack('!HH', size1, size2)
    print(f"Length Header: {sizes.hex()} {size1} {size2} {length}")
    return sizes
def receiveLength(sock):
    try:
        length = socket_recv_n(sock, 4)
    except Exception as e:
        print(f"Error receiving data!")
        print(f"Exception: {e}")
        return 0
    if len(length) < 4:
        print("Connection closed!")
        return 0
    size1, size2 = struct.unpack('!HH', length)
    actualLength = (size1 + size2) % 0x10000
    print(f"Length Header: {length.hex()} {size1} {size2} {actualLength}")
    return actualLength

