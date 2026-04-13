import os

print(eval("1+1"))
print(eval("os.getcwd()"))
print(os.chmod('test.txt', 0o777))


# A user-defined method named "eval" should not get flagged.
class Test(object):
    def eval(self):
        print("hi")
    def foo(self):
        self.eval()

Test().eval()
