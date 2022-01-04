COMMAND_TYPES = [ 'register',
                  'init',
                  'tasking_dir',
                  'dir_list',
                  'file_download',
                  'file_upload',
                  'fin'
                ]
class CommandKey():
    def __init__(self):
        self.key = dict()
        for idx,cmd in enumerate(COMMAND_TYPES):
            self.key[cmd] = idx + 1

