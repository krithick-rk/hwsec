from adapters.storage_adapter import StorageAdapter


class FileService:
    def __init__(self, config):
        self.config = config
        self.adapter = StorageAdapter(config)

    def read_file(self, filename):
        return self.adapter.read(filename)

    def preview_file(self, filename):
        content = self.adapter.read_preview(filename)
        if content is None:
            return None
        if isinstance(content, str):
            return content[:500]
        return content

    def list_files(self):
        return self.adapter.list_files()

    def init_storage(self):
        self.adapter.init_storage()
