import zipfile
import tempfile
import os

# B203: HIGH — sem validação nenhuma
with zipfile.ZipFile("archive.zip") as zf:
    zf.extractall(tempfile.mkdtemp())

# B203: HIGH — path especificado mas sem validar membros
dest = "/tmp/output"
with zipfile.ZipFile("archive.zip") as zf:
    zf.extractall(path=dest)

# B203: MEDIUM — members passado mas sem validação de path confirmada
with zipfile.ZipFile("archive.zip") as zf:
    zf.extractall(path=dest, members=zf.namelist())

def safe_extract(zf, destination):
    destination = os.path.realpath(destination)
    for member in zf.namelist():
        member_path = os.path.realpath(os.path.join(destination, member))
        if not member_path.startswith(destination + os.sep):
            raise ValueError("Zip Slip detected: %s" % member)
        zf.extract(member, destination)
