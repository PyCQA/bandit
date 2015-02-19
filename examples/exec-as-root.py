from nova import utils

utils.execute('gcc --version')
utils.execute('gcc --version', run_as_root=False)
utils.execute('gcc --version', run_as_root=True)
utils.trycmd('gcc --version')
utils.trycmd('gcc --version', run_as_root=True)
