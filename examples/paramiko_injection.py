import paramiko

# this is not safe
paramiko.exec_command('something; reallly; unsafe')

# this is safe
paramiko.connect('somehost')

# this is not safe
SSHClient.invoke_shell('something; bad; here\n')

