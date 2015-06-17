import paramiko

# this is not safe
paramiko.exec_command('something; reallly; unsafe')

# this is safe
paramiko.connect('somehost')

# this should not be detected
somelib.exec_command('this; is; indeterminately; unsafe')

# this is not safe
paramiko.invoke_shell('something; bad; here\n')

# should not be detected
somelib.invoke_shell('this; is; indeterminately; unsafe')

