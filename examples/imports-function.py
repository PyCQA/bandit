os = __import__("os")
pickle = __import__("pickle")
sys = __import__("sys")
subprocess = __import__("subprocess")

# this has been reported in the wild, though it's invalid python
# see bug https://bugs.launchpad.net/bandit/+bug/1396333
__import__()

# TODO(??): bandit can not find this one unfortunately (no symbol tab)
a = 'subprocess'
__import__(a)
