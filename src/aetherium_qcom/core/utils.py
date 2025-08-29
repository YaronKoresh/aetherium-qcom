# aetherium_qcom/core/utils.py
import os
import hashlib
import socket
from contextlib import contextmanager

@contextmanager
def cwd(dir_path=None):
    """
    Context manager to change the CWD. Defaults to the package directory.
    This is useful for ensuring profile.json, keys, etc., are read/written correctly.
    """
    if not dir_path:
        dir_path = os.path.dirname(os.path.realpath(__file__))
    
    owd = os.getcwd()
    try:
        os.chdir(dir_path)
        yield dir_path
    finally:
        os.chdir(owd)

class CodeHasher:
    @staticmethod
    def get_source_hash(reference_file_path):
        """
        Hashes all .py files in the package directory to ensure integrity.
        It uses the provided file path to locate the package root.
        """
        try:
            root = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.realpath(reference_file_path)
            )))
            sub_roots = ["assets", "scripts", "src"]

            hasher = hashlib.sha256()
            
            all_files = [
                os.path.join(root,"LICENSE"),
                os.path.join(root,"pyproject.toml"),
                os.path.join(root,"README.md"),
            ]
            for sub_root in sub_roots:
                for current_root, _, files in os.walk(os.path.join(root,sub_root)):
                    for file in files:
                        all_files.append(os.path.join(current_root, file))

            # Sort the file paths to ensure a consistent hashing order every time
            for file_path in sorted(all_files):
                with open(file_path, 'rb') as f:
                    hasher.update(f.read())

            return hasher.hexdigest()
        except (TypeError, OSError) as e:
            print(f"Error hashing source code: {e}")
            return None

def get_free_ports(count=2):
    """Finds and returns a specified number of free ports."""
    sockets, ports = [], []
    for _ in range(count):
        s = socket.socket()
        s.bind(('', 0))
        ports.append(s.getsockname()[1])
        sockets.append(s)
    for s in sockets:
        s.close()
    return ports