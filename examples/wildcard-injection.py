import os as o
import subprocess as subp

# Vulnerable to wildcard injection
o.system("tar xvzf *")
o.system('chown *')
o.popen2('chmod *')
subp.Popen('chown *', shell=True)

# Not vulnerable to wildcard injection
subp.Popen('rsync *')
subp.Popen("chmod *")
subp.Popen(['chown', '*'])
subp.Popen(["chmod", sys.argv[1], "*"],
                 stdin=subprocess.PIPE, stdout=subprocess.PIPE)
o.spawnvp(os.P_WAIT, 'tar', ['tar', 'xvzf', '*'])
