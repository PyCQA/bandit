# trigger warn for temp file
x = """
      /tmp
"""

# no finding
"abc"

# no finding, docstring
def f():
    """
    /tmp
    """
# trigger warning for tempfile
def f():
    x='''
    /tmp
    '''

