import pathlib

filename = 'foobar'
p1 = pathlib.Path(filename)
p1.chmod(0o666)

symlink = 'link'
p2 = pathlib.Path(symlink)
p2.lchmod(0o777)
