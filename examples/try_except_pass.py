# bad
try:
    a = 1
except Exception:
    pass


# bad
try:
    a = 1
except Exception:
    pass


# bad
try:
    a = 1
except ZeroDivisionError:
    pass
except Exception:
    a = 2


# good
try:
    a = 1
except Exception:
    a = 2


# silly, but ok
try:
    a = 1
except Exception:
    pass
    a = 2
