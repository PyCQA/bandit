# bad
for i in {0,1}:
    try:
        a = i
    except Exception:
        continue


# bad
while keep_trying:
    try:
        a = 1
    except Exception:
        continue


# bad
for i in {0,2}:
    try:
        a = i
    except ZeroDivisionError:
        continue
    except Exception:
        a = 2


# good
while keep_trying:
    try:
        a = 1
    except Exception:
        a = 2
