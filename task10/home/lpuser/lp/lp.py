import os
import sys
import stat
import socket
import threading
import socketserver
import time
import uuid
from ipaddress import IPv4Address
BASE = os.path.dirname(os.path.abspath(__file__))
from protocol import *
from commands import *
from lpcrypt import *
known_uuids = set()
TASKING_ROOT = '/tmp/endpoints/'
TASKING_ROOT_MAXSZ = 500000000
PARTIAL_UPLOADS = {}
PROTO_CONFIG = None
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    param_key = None
    command_key = None
    uuid = None
    session_key = None
    initialized = False
    continueSession = True
    def setup(self):
        print("Setup session")
        self.param_key = ParamKey(PROTO_CONFIG)
        self.command_key = CommandKey()
        self.public_key = PROTO_CONFIG['pub']
        self.private_key = PROTO_CONFIG['priv']
        self.session_key = serverInitializeCrypt(self.request,
                                                 self.public_key,
                                                 self.private_key)
    def handle(self):
        while self.continueSession:
            msg = self.recv()
            if msg:
                reply = self.process_msg(msg)
                if reply:
                    self.send(reply)
            else:
                self.continueSession = False
            print(f"Success!")
    def send(self, msg) -> bool:
        print(f"Sending data...")
        ciphertext = encryptMessage(self.session_key, msg)
        print(f"Sending data...")
        try:
            self.request.sendall(ciphertext)
        except Exception as e:
            print(f"Error sending data!")
            print(f"Exception: {e}")
            return False
        print(f"Success!")
        return True
    def recv(self):
        print(f"Receiving data...")
        if self.uuid and self.session_key:
            print(f"\t-> UUID: {self.uuid} Key: {self.session_key.hex()}")
        msgLen = receiveLength(self.request)
        if msgLen < 0 or msgLen >= 10000:
            print(f"Got a message that seems a bit on the long side! {msgLen}")
            return False
        if msgLen == 0:
            print(f"Other end closed the connection.")
            return False
        try:
            ciphertext = self.request.recv(msgLen)
        except Exception as e:
            print(f"Error sending data!")
            print(f"Exception: {e}")
            return False
        if ciphertext == b'':
            return None
        print(f"Got {msgLen} bytes: {ciphertext.hex()[:60]}{'...' if len(ciphertext.hex()) > 60 else ''}")
        msg = decryptMessage(self.session_key, ciphertext)
        print(f"Success!")
        return msg
    def process_msg(self, in_msg):
        print("Processing Message")
        print("==================")
        try:
            in_params = parse_msg(self.param_key, in_msg)
        except Exception as e:
            print(f"{e}")
            return None
        print(f"Input params:")
        for k in in_params:
            val = str(in_params[k])
            if len(val) > 50:
                val = val[:50] + '...'
            print(f'\t{k} => {val}')
        if 'command_type' not in in_params:
            error_code = 0x00000011
            print(f"Message does not contain a command_type!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        command_type = in_params['command_type']
        if command_type not in self.command_key.key.values():
            error_code = 0x00000022
            print(f"Invalid command_type {command_type}!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        elif command_type == self.command_key.key['init']:
            print("Received init command")
            self.send(self.process_init(in_params))
            self.initialized = True
            return None
        elif command_type == self.command_key.key['tasking_dir']:
            print("Received init command")
            return self.process_tasking_dir(in_params)
        elif command_type == self.command_key.key['dir_list']:
            print("Received dir list command")
            return self.process_dir_list(in_params)
        elif command_type == self.command_key.key['file_download']:
            print("Received file_download command")
            return self.process_file_download(in_params)
        elif command_type == self.command_key.key['file_upload']:
            print("Received file upload command")
            return self.process_file_upload(in_params)
        elif command_type == self.command_key.key['fin']:
            print("Received fin command")
            self.continueSession = False
            return self.process_fin(in_params)
        error_code = 0x00000033
        print(f"Have not defined a process function for command_type {command_type}!")
        print(f"Returning error code: {error_code}")
        return create_error_msg(self.param_key, error_code)
    def process_init(self, in_params):
        if in_params['command_type'] != self.command_key.key['init']:
            raise ValueError(f"Error: Somehow trying to process_register msg for command_type {in_params['command_type']} when that value should be {self.command_key.key['init']}")
        if set(in_params.keys()) != set(['command_type', 'uuid']):
            error_code = 0x00000044
            print(f"Invalid in_params keys {in_params.keys()}!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        known_uuids.add(in_params['uuid'])
        self.uuid = in_params['uuid']
        uuid_root = os.path.join(TASKING_ROOT, in_params['uuid'])
        if not os.path.exists(uuid_root):
            os.makedirs(uuid_root)
            os.makedirs(os.path.join(uuid_root, 'tasking'))
            os.makedirs(os.path.join(uuid_root, 'uploads'))
        return create_error_msg(self.param_key, 0)
    def process_tasking_dir(self, in_params):
        if in_params['command_type'] != self.command_key.key['tasking_dir']:
            raise ValueError(f"Error: Somehow trying to process_register msg for command_type {in_params['command_type']} when that value should be {self.command_key.key['tasking_dir']}")
        if set(in_params.keys()) != set(['command_type', 'uuid']):
            error_code = 0x00000044
            print(f"Invalid in_params keys {in_params.keys()}!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        if in_params['uuid'] not in known_uuids:
            error_code = 0x00000055
            print(f"Input uuid {in_params['uuid']} could not be found in known uuids {known_uuids}")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        tasking_dir = os.path.join(TASKING_ROOT, in_params['uuid'], 'tasking')
        out_params = OrderedDict()
        out_params['dir_name'] = tasking_dir
        return create_msg(self.param_key, out_params)
    def process_dir_list(self, in_params):
        if in_params['command_type'] != self.command_key.key['dir_list']:
            raise ValueError(f"Error: Somehow trying to process_register msg for command_type {in_params['command_type']} when that value should be {self.command_key.key['dir_list']}")
        if set(in_params.keys()) != set(['command_type', 'uuid', 'dir_name']):
            error_code = 0x00000044
            print(f"Invalid in_params keys {in_params.keys()}!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        if in_params['uuid'] not in known_uuids:
            error_code = 0x00000055
            print(f"Input uuid {in_params['uuid']} could not be found in known uuids {known_uuids}")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        requested_dir = os.path.join(TASKING_ROOT,
                                     in_params['uuid'],
                                     in_params['dir_name'])
        try:
                file_names = os.listdir(requested_dir)
        except NotADirectoryError:
            error_code = 0x00000060
            print(f"Requested directory {requested_dir} is not a directory!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        except FileNotFoundError:
            error_code = 0x00000061
            print(f"Requested directory {requested_dir} does not exist!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        except PermissionError:
            error_code = 0x00000064
            print(f"Permissions error for {requested_file}.")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)            
        except Exception as e:
            error_code = 0x0000007F
            print(f"Some other error happened. {str(e)}")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        out_params = OrderedDict()
        if len(file_names) == 0:
            file_names.append('')
        out_params['dir_listing'] = file_names
        return create_msg(self.param_key, out_params)
    def process_file_download(self, in_params):
        if in_params['command_type'] != self.command_key.key['file_download']:
            raise ValueError(f"Error: Somehow trying to process_register msg for command_type {in_params['command_type']} when that value should be {self.command_key.key['file_download']}")
        if set(in_params.keys()) != set(['command_type', 'uuid', 'dir_name', 'file_name']):
            error_code = 0x00000044
            print(f"Invalid in_params keys {in_params.keys()}!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        requested_file = os.path.join(TASKING_ROOT,
                                      in_params['uuid'],
                                      in_params['dir_name'],
                                      in_params['file_name'])
        try:
            fd = open(requested_file, 'rb')
            content = fd.read(4000)
        except FileNotFoundError:
            error_code = 0x00000061
            print(f"Requested file {requested_file} does not exist!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        except IsADirectoryError:
            error_code = 0x00000063
            print(f"Requested file {requested_file} is a directory!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        except PermissionError:
            error_code = 0x00000064
            print(f"Permissions error for {requested_file}.")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)            
        except:
            error_code = 0x0000007F
            print(f"Some other error happened.")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        out_params = OrderedDict()
        out_params['file_contents'] = content
        return create_msg(self.param_key, out_params)
    def clearStalePartials(self):
        """
        Helper function to maintain PARTIAL_UPLOAD structure
        used to hold uploads until all parts are uploaded
        TODO: we can still DOS, either through large uploads 
        or many uploads under the timelimit, do we care?
        """
        for k, v in PARTIAL_UPLOADS.items():
            if time.time() - v['timestamp'] > 1800:
                print(f'Deleting partial uploads entry for: {k}')
                del PARTIAL_UPLOADS[k]
    def process_file_upload(self, in_params):
        if in_params['command_type'] != self.command_key.key['file_upload']:
            raise ValueError(f"Error: Somehow trying to process_register msg for command_type {in_params['command_type']} when that value should be {self.command_key.key['file_upload']}")
        if set(in_params.keys()) != set(['command_type', 'uuid', 'dir_name', 'file_name', 'file_contents', 'file_flag']):
            error_code = 0x00000044
            print(f"Invalid in_params keys {in_params.keys()}!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        if '..' in in_params['dir_name'] or '..' in in_params['file_name']:
            error_code = 0x0000006F
            print(f"Malformed dir_name or file_name: {in_params['dir_name']} {in_params['file_name']}")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)      
        taskingRootSize = sum(os.path.getsize(f) for f in os.listdir(TASKING_ROOT) if os.path.isfile(f))      
        if  taskingRootSize > TASKING_ROOT_MAXSZ:
            error_code = 0x0000006E
            print(f"No more space on server...")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)    
        fp = os.path.join(TASKING_ROOT, in_params['uuid'], 'uploads', in_params['dir_name'])
        if not os.path.exists(fp):
            os.makedirs(fp)
        fp = os.path.join(fp, in_params['file_name'])
        if in_params['file_flag']:
            self.clearStalePartials()
            if in_params['file_name'] in PARTIAL_UPLOADS:
                PARTIAL_UPLOADS[in_params['file_name']]['file_contents'] += in_params['file_contents']
            else:
                PARTIAL_UPLOADS[in_params['file_name']] = {'file_contents' : in_params['file_contents']}
                PARTIAL_UPLOADS[in_params['file_name']]['timestamp'] = time.time()
        else:
            if in_params['file_name'] in PARTIAL_UPLOADS:
                PARTIAL_UPLOADS[in_params['file_name']]['file_contents'] += in_params['file_contents']
                with open(fp,'wb') as f:
                    f.write(PARTIAL_UPLOADS[in_params['file_name']]['file_contents'])
                del PARTIAL_UPLOADS[in_params['file_name']]
            else:
                with open(fp,'wb') as f:
                    f.write(in_params['file_contents'])
        out_params = OrderedDict()
        out_params['error_code'] = 0
        return create_msg(self.param_key, out_params)
    def process_fin(self, in_params):
        if in_params['command_type'] != self.command_key.key['fin']:
            raise ValueError(f"Error: Somehow trying to process_register msg for command_type {in_params['command_type']} when that value should be {self.command_key.key['fin']}")
        if set(in_params.keys()) != set(['command_type']):
            error_code = 0x00000044
            print(f"Invalid in_params keys {in_params.keys()}!")
            print(f"Returning error code: {error_code}")
            return create_error_msg(self.param_key, error_code)
        return create_error_msg(self.param_key, 0)
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass
if __name__ == "__main__":
    ip = '0.0.0.0'
    port = 6666
    PROTO_CONFIG_PATH = os.path.join(BASE, 'protocol.json')
    if os.path.exists(PROTO_CONFIG_PATH):
        PROTO_CONFIG = json.load(open(PROTO_CONFIG_PATH))
    else:
        raise Exception("Missing protocol.json!")
    os.makedirs(TASKING_ROOT, exist_ok = True)
    socketserver.TCPServer.allow_reuse_address = True
    server = ThreadedTCPServer((ip, port), ThreadedTCPRequestHandler)
    ip, port = server.server_address
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    print("Server loop running in thread:", server_thread.name)

