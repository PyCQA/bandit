import subprocess
from subprocess import Popen as pop


def Popen(*args, **kwargs):
    print('hi')

pop('/bin/gcc --version', shell=True)
Popen('/bin/gcc --version', shell=True)

subprocess.Popen('/bin/gcc --version', shell=True)
subprocess.Popen(['/bin/gcc', '--version'], shell=False)
subprocess.Popen(['/bin/gcc', '--version'])

subprocess.call(["/bin/ls",
                 "-l"
                 ])
subprocess.call('/bin/ls -l', shell=True)

subprocess.check_call(['/bin/ls', '-l'], shell=False)
subprocess.check_call('/bin/ls -l', shell=True)

subprocess.check_output(['/bin/ls', '-l'])
subprocess.check_output('/bin/ls -l', shell=True)
