import commands
import popen2


print commands.getstatusoutput('echo / | xargs ls')
print commands.getoutput('echo / | xargs ls')

# This one is safe.
print commands.getstatus('echo / | xargs ls')

print popen2.popen2('echo / | xargs ls')[0].read()
print popen2.popen3('echo / | xargs ls')[0].read()
print popen2.popen4('echo / | xargs ls')[0].read()
print popen2.Popen3('echo / | xargs ls').fromchild.read()
print popen2.Popen4('echo / | xargs ls').fromchild.read()
