import os as o
import subprocess as subp

os.system("tar xvzf *")
subprocess.Popen("chmod *")
o.system('chown *')
subp.Popen('rsync *')
subprocess.Popen(['chown', '*'])
subprocess.Popen(["chmod", sys.argv[1], "*"],
                 stdin=subprocess.PIPE, stdout=subprocess.PIPE)
