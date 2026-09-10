import os


class Config:
    BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'storage')

    def get_base_dir(self):
        return self.BASE_DIR
