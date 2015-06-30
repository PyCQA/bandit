import utils
import utils as u

u.execute('/bin/gcc --version', shell=True)
utils.execute('/bin/gcc --version', shell=True)
u.execute_with_timeout('/bin/gcc --version', shell=True)
utils.execute_with_timeout('/bin/gcc --version', shell=True)
utils.execute_with_timeout(['/bin/gcc', '--version'], shell=False)
