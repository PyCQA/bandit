import subprocess  # nosec: import_subprocess
from cryptography.hazmat.primitives import hashes
hashes.SHA1()  # nosec: md5
subprocess.Popen('/bin/ls *', shell=True) #nosec (on the line)
subprocess.Popen('/bin/ls *', #nosec (at the start of function call)
                 shell=True)
subprocess.Popen('/bin/ls *',
                 shell=True)  #nosec (on the specific kwarg line)
subprocess.Popen('#nosec', shell=True)
subprocess.Popen('/bin/ls *', shell=True) # type: ... # nosec # noqa: E501 ; pylint: disable=line-too-long
subprocess.Popen('/bin/ls *', shell=True) # type: ... # nosec B607 # noqa: E501 ; pylint: disable=line-too-long
subprocess.Popen('/bin/ls *', shell=True)  #nosec subprocess_popen_with_shell_equals_true (on the line)
subprocess.Popen('#nosec', shell=True) # nosec B607, B602
subprocess.Popen('#nosec', shell=True) # nosec B607 B602
subprocess.Popen('/bin/ls *', shell=True)  # nosec subprocess_popen_with_shell_equals_true start_process_with_partial_path
subprocess.Popen('/bin/ls *', shell=True) # type: ... # noqa: E501 ; pylint: disable=line-too-long # nosec
subprocess.Popen('#nosec', shell=True) # nosec B607, B101
subprocess.Popen('#nosec', shell=True) # nosec B602, subprocess_popen_with_shell_equals_true
