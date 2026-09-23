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
# check that nosec in nested dict does not cause "higher" annotations to be ignored
# reproduction of https://github.com/PyCQA/bandit/issues/1003
example = {
    'S3_CONFIG_PARAMS': dict(  # nosec B106
        aws_access_key_id='key_goes_here',
        aws_secret_access_key='secret_goes_here',
        endpoint_url='s3.amazonaws.com',
    ),
    'LOCALFS_BASEDIR': '/var/tmp/herp',  # nosec B108
    'ALPINE_APORTS_DIR': '/tmp/derp',  # nosec B108
}
