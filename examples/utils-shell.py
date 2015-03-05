import utils
import utils as u

u.execute('gcc --version', shell=True)
utils.execute('gcc --version', shell=True)
u.execute_with_timeout('gcc --version', shell=True)
utils.execute_with_timeout('gcc --version', shell=True)
utils.execute_with_timeout(['gcc', '--version'], shell=False)


