# Regression example for issue #1171: B202 should still fire on extractall when
# tarfile is brought in with a from-import (no bare "import tarfile").
import tempfile
from tarfile import TarFile


def unsafe_from_import_handler(filename):
    tar = TarFile(filename)
    tar.extractall(path=tempfile.mkdtemp())
    tar.close()


def filter_data_from_import_handler(filename):
    tar = TarFile(filename)
    tar.extractall(path=tempfile.mkdtemp(), filter="data")
    tar.close()
