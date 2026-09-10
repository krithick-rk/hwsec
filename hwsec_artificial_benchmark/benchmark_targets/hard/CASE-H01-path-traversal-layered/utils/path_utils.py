import os


class PathUtils:
    def join_path(self, base_dir, filename):
        return os.path.join(base_dir, filename)

    def join_path_safe(self, base_dir, filename):
        base_real = os.path.realpath(base_dir)
        target = os.path.realpath(os.path.join(base_dir, filename))
        if not target.startswith(base_real + os.sep) and target != base_real:
            return None
        return target
