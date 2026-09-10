import os


class Config:
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    XML_FILE = os.path.join(DATA_DIR, 'users.xml')
