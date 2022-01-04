from collections import OrderedDict
from ipaddress import IPv4Address
from binascii import hexlify,unhexlify
import socket
import os
import json
DEBUG = False
PARAM_TYPES = [ 'command_type',
                'session_token',
                'uuid',
                'ip_addr',
                'port',
                'dir_name',
                'dir_listing',
                'file_name',
                'file_contents',
                'file_flag',
                'error_code'
              ]
ARRAY_PARAMS = [ 'dir_listing'
               ]
BASE = os.path.dirname(os.path.abspath(__file__))
def int_to_bytes(x: int, length=None) -> bytes:
    if not length:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')
    else:
        return x.to_bytes(length, 'big')
def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')
def print_bytes(in_bytes):
    if DEBUG:
        for b in in_bytes:
            print(f"{hex(b)[2:].zfill(2)} ",end='')
        print()
class Param():
    def __init__(self, param_type: str, param_id: int):
        if param_type not in PARAM_TYPES:
            print(f"Error: Invalid param_type: {param_type}")
            return None
        self.param_type = param_type
        self.param_id   = int_to_bytes(param_id)
        if self.param_type == 'command_type':
            self.min_length = self.length = 2
        elif self.param_type == 'session_token':
            self.min_length = self.length = 16
        elif self.param_type == 'uuid':
            self.min_length = self.length = 16
        elif self.param_type == 'ip_addr':
            self.min_length = self.length = 4
        elif self.param_type == 'port':
            self.min_length = self.length = 2
        elif self.param_type == 'dir_name':
            self.length = None
            self.min_length = 1
        elif self.param_type == 'dir_listing':
            self.length = None
            self.min_length = 1
        elif self.param_type == 'file_name':
            self.length = None
            self.min_length = 1
        elif self.param_type == 'file_contents':
            self.length = None
            self.min_length = 0
        elif self.param_type == 'file_flag':
            self.min_length = self.length = 1
        elif self.param_type == 'error_code':
            self.min_length = self.length = 4
        else:
            raise ValueError(f"Invalid param_type {self.param_type}. How did this happen?!")
    def to_bytes(self, val):
        if self.param_type == 'command_type':
            if not isinstance(val, int):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            return int_to_bytes(val, self.length)
        elif self.param_type == 'session_token':
            if not isinstance(val, str):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            clean_val = val.replace('-','')
            val_bytes = unhexlify(clean_val)
            return (self.length - len(val_bytes)) * b"\x00" + val_bytes
        elif self.param_type == 'uuid':
            if not isinstance(val, str):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            clean_val = val.replace('-','')
            val_bytes = unhexlify(clean_val)
            return (self.length - len(val_bytes)) * b"\x00" + val_bytes
        elif self.param_type == 'ip_addr':
            if not isinstance(val, str):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            return IPv4Address(val).packed[::-1]
        elif self.param_type == 'port':
            if not isinstance(val, int):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            return int_to_bytes(val, self.length)
        elif self.param_type == 'dir_name':
            if not isinstance(val, str):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            return val.encode('utf-8') + b'\x00'
        elif self.param_type == 'dir_listing':
            if not isinstance(val, str):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            return val.encode('utf-8') + b'\x00'
        elif self.param_type == 'file_name':
            if not isinstance(val, str):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            return val.encode('utf-8') + b'\x00'
        elif self.param_type == 'file_contents':
            if not isinstance(val, bytes):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            return val
        elif self.param_type == 'file_flag':
            if not isinstance(val, bool):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            if val:
                return b'\x01'
            else:
                return b'\x00'
        elif self.param_type == 'error_code':
            if not isinstance(val, int):
                raise ValueError(f"Invalid type for val {val}: {type(val)}")
            return int_to_bytes(val, self.length)
        else:
            raise ValueError(f"Invalid param_type {self.param_type}. How did this happen?!")
    def from_bytes(self, in_bytes: bytes):
        if ((self.length is None and len(in_bytes) < self.min_length) or
            (self.length is not None and len(in_bytes) != self.length)):
            raise ValueError(f"Invalid length for param {self.param_type} (min: {self.min_length}, expect: {self.length})")
        if self.param_type == 'command_type':
            return int_from_bytes(in_bytes)
        elif self.param_type == 'session_token':
            val = hexlify(in_bytes).decode()
            return f"{val[0:8]}-{val[8:12]}-{val[12:16]}-{val[16:20]}-{val[20:]}"
        elif self.param_type == 'uuid':
            val = hexlify(in_bytes).decode()
            return f"{val[0:8]}-{val[8:12]}-{val[12:16]}-{val[16:20]}-{val[20:]}"
        elif self.param_type == 'ip_addr':
            return str(IPv4Address(in_bytes[::-1]))
        elif self.param_type == 'port':
            return int_from_bytes(in_bytes)
        elif self.param_type == 'dir_name':
            return in_bytes.decode().rstrip('\x00')
        elif self.param_type == 'dir_listing':
            return in_bytes.decode().rstrip('\x00')
        elif self.param_type == 'file_name':
            return in_bytes.decode().rstrip('\x00')
        elif self.param_type == 'file_contents':
            return in_bytes
        elif self.param_type == 'file_flag':
            return bool(in_bytes[0])
        elif self.param_type == 'error_code':
            return int_from_bytes(in_bytes)
        else:
            raise ValueError(f"Invalid param_type {self.param_type}. How did this happen?!")
class ParamKey():
    def __init__(self, protoParams):
        self.magic_init = int_to_bytes(protoParams['s'])
        self.magic_fin  = int_to_bytes(protoParams['e'])
        self.param_base = protoParams['b']
        self.key = dict()
        for idx,param in enumerate(PARAM_TYPES):
            self.key[param] = Param(param, self.param_base + 4*idx)
        self.rev_key = dict()
        for param in PARAM_TYPES:
            self.rev_key[self.key[param].param_id] = param
def param_to_bytes(param_key: ParamKey, param, val):
    if param not in param_key.key:
        raise ValueError(f"Invalid param: {param}")
    msg = b''
    val_bytes = param_key.key[param].to_bytes(val)
    val_len = len(val_bytes).to_bytes(2, 'big')
    print(f"\tParam ID: {hexlify(param_key.key[param].param_id).decode()}")
    print(f"\tParam length: {hexlify(val_len).decode()}")
    print(f"\tParam value: {hexlify(val_bytes).decode()[:60]}{'...' if len(hexlify(val_bytes).decode()) > 60 else ''}")
    msg += param_key.key[param].param_id
    msg += val_len
    msg += val_bytes
    return msg
def create_msg(param_key: ParamKey, params: OrderedDict):
    print()
    print(f"Creating message")
    print(f"================")
    print(f"Params: ")
    for param in params:
        printable = str(params[param])
        if len(printable) > 50:
            printable = printable[:50] + '...'
        print(f'\t{param} => {printable}')
    msg = b''
    print(f"Adding magic_init: {hexlify(param_key.magic_init).decode()}")
    msg += param_key.magic_init
    for param in params:
        printable = str(params[param])
        if len(printable) > 50:
            printable = printable[:50] + '...'
        print(f"Parsing parameter {param}: {printable}")
        if param not in param_key.key:
            raise ValueError(f"Invalid param: {param}. Should match something in param_key.key {param_key.key.keys()}")
        if param in ARRAY_PARAMS:
            for val in params[param]:
                msg += param_to_bytes(param_key, param, val)
        else:
            val = params[param]
            msg += param_to_bytes(param_key, param, val)
    print(f"Adding magic_fin: {hexlify(param_key.magic_fin).decode()}")
    msg += param_key.magic_fin
    print()
    print("Final message:")
    print_bytes(msg)
    return msg
def parse_msg(param_key: ParamKey, msg: bytes):
    print()
    print("Parsing message")
    print("===============")
    print(f"Message:")
    print_bytes(msg)
    if len(msg) == 0:
        raise ValueError(f"Error: can't parse an empty message!")
    out_params = OrderedDict()
    if not msg[0:4] == param_key.magic_init:
        raise ValueError(f"Message bytes {hexlify(msg[0:4]).decode()} don't match magic_init {hexlify(param_key.magic_init).decode()}")
    if not msg[-4:] == param_key.magic_fin:
        raise ValueError(f"Message bytes {hexlify(msg[-4:]).decode()} don't match magic_fin {hexlify(param_key.magic_fin).decode()}")
    print(f"Validated magic init and fin")
    index = 4
    while index < len(msg) - 4:
        if (len(msg) - 4) - index < 5:
            print(f"Ignoring final bytes: {hexlify(msg[index:]).decode()}")
            break
        print(f"Parsing parameter: {hexlify(msg[index:index+4]).decode()}")
        param_type_bytes = msg[index:index+2]
        if param_type_bytes not in param_key.rev_key:
            raise ValueError(f"\tError: {hexlify(param_type_bytes).decode()} is not a valid param_type")
        param_type = param_key.rev_key[param_type_bytes]
        param_len = int_from_bytes(msg[index+2:index+4])
        if (len(msg) - 4) - index < param_len:
            raise ValueError(f"\tParameter length {param_len} is too long for the remaining bytes in this message")
        index += 4
        val_bytes = msg[index:index+param_len]
        val = param_key.key[param_type].from_bytes(val_bytes)
        if val is None:
            raise ValueError(f"Error converting val_bytes {val_bytes} from bytes")
        if param_type in ARRAY_PARAMS:
            if param_type not in out_params:
                out_params[param_type] = list()
            out_params[param_type].append(val)
        else:
            out_params[param_type] = val
        index += param_len
    print("Final params parsed from message:")
    for p in out_params:
        val = str(out_params[p])
        if len(val) > 50:
            val = val[:50] + '...'
        print(f"\t{p}: {val}")
    return out_params
def socket_recv_n(sock, n):
    rv = b''
    while len(rv) < n:
        new_data = sock.recv(n - len(rv))
        if len(new_data) == 0:
            break
        rv += new_data
    return rv
def create_error_msg(param_key: ParamKey, error_code: int):
    params = OrderedDict()
    params['error_code'] = error_code
    return create_msg(param_key, params)

