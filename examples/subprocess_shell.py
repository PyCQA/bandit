import subprocess
from subprocess import Popen as pop


def Popen(*args, **kwargs):
    print('hi')

pop('gcc --version', shell=True)
Popen('gcc --version', shell=True)

subprocess.Popen('gcc --version', shell=True)
subprocess.Popen(['gcc', '--version'], shell=False)
subprocess.Popen(['gcc', '--version'])

subprocess.call(["ls",
                 "-l"
                 ])
subprocess.call('ls -l', shell=True)

subprocess.check_call(['ls', '-l'], shell=False)
subprocess.check_call('ls -l', shell=True)

subprocess.check_output(['ls', '-l'])
subprocess.check_output('ls -l', shell=True)
