from subprocess import Popen as pop


def Popen():
    print('hi')

pop('gcc --version', shell=True)
Popen('gcc --version', shell=True)
