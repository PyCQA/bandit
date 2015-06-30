import commands
import popen2


print(commands.getstatusoutput('/bin/echo / | xargs ls'))
print(commands.getoutput('/bin/echo / | xargs ls'))

# This one is safe.
print(commands.getstatus('/bin/echo / | xargs ls'))

print(popen2.popen2('/bin/echo / | xargs ls')[0].read())
print(popen2.popen3('/bin/echo / | xargs ls')[0].read())
print(popen2.popen4('/bin/echo / | xargs ls')[0].read())
print(popen2.Popen3('/bin/echo / | xargs ls').fromchild.read())
print(popen2.Popen4('/bin/echo / | xargs ls').fromchild.read())
