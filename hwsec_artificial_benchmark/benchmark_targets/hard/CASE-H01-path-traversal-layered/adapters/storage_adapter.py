import os
from utils.path_utils import PathUtils


class StorageAdapter:
    def __init__(self, config):
        self.config = config
        self.base_dir = config.get_base_dir()
        self.path_utils = PathUtils()

    def read(self, filename):
        filepath = self.path_utils.join_path(self.base_dir, filename)
        if filepath is None:
            return {'error': 'invalid path'}
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None
        except IsADirectoryError:
            return {'error': 'path is a directory'}

    def read_preview(self, filename):
        filepath = self.path_utils.join_path_safe(self.base_dir, filename)
        if filepath is None:
            return {'error': 'invalid path'}
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None
        except IsADirectoryError:
            return {'error': 'path is a directory'}

    def list_files(self):
        if not os.path.exists(self.base_dir):
            return []
        return os.listdir(self.base_dir)

    def init_storage(self):
        os.makedirs(self.base_dir, exist_ok=True)
        for name, content in [('readme.txt', 'Welcome to the file service.\n'),
                              ('notes.txt', 'Some important notes.\n'),
                              ('config.txt', 'default configuration\n')]:
            path = os.path.join(self.base_dir, name)
            with open(path, 'w') as f:
                f.write(content)
