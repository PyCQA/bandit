subprocess.Popen('/bin/ls *', shell=True) #nosec (on the line)
subprocess.Popen('/bin/ls *', #nosec (at the start of function call)
                 shell=True)
subprocess.Popen('/bin/ls *',
                 shell=True)  #nosec (on the specific kwarg line)
