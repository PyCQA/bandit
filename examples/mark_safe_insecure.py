import os
from django.utils import safestring


def insecure_function(text, cls=''):
    return '<h1 class="{cls}">{text}</h1>'.format(text=text, cls=cls)


my_insecure_str = insecure_function('insecure', cls='" onload="alert(\'xss\')')
safestring.mark_safe(my_insecure_str)
safestring.SafeText(my_insecure_str)
safestring.SafeUnicode(my_insecure_str)
safestring.SafeString(my_insecure_str)
safestring.SafeBytes(my_insecure_str)


def try_insecure(cls='" onload="alert(\'xss\')'):
    try:
        my_insecure_str = insecure_function('insecure', cls=cls)
    except Exception:
        my_insecure_str = 'Secure'
    safestring.mark_safe(my_insecure_str)


def except_insecure(cls='" onload="alert(\'xss\')'):
    try:
        my_insecure_str = 'Secure'
    except Exception:
        my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe(my_insecure_str)


def try_else_insecure(cls='" onload="alert(\'xss\')'):
    try:
        if 1 == random.randint(0, 1):  # nosec
            raise Exception
    except Exception:
        my_insecure_str = 'Secure'
    else:
        my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe(my_insecure_str)


def finally_insecure(cls='" onload="alert(\'xss\')'):
    try:
        if 1 == random.randint(0, 1):  # nosec
            raise Exception
    except Exception:
        print "Exception"
    else:
        print "No Exception"
    finally:
        my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe(my_insecure_str)


def format_arg_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>{} {}</b>'.format(my_insecure_str, 'STR'))


def format_startarg_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>{}</b>'.format(*[my_insecure_str]))


def format_keywords_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>{b}</b>'.format(b=my_insecure_str))


def format_kwargs_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>{b}</b>'.format(**{'b': my_insecure_str}))


def percent_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>%s</b>' % my_insecure_str)


def percent_list_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>%s %s</b>' % (my_insecure_str, 'b'))


def percent_dict_insecure(cls='" onload="alert(\'xss\')'):
    my_insecure_str = insecure_function('insecure', cls=cls)
    safestring.mark_safe('<b>%(b)s</b>' % {'b': my_insecure_str})


def import_insecure():
    import sre_constants
    safestring.mark_safe(sre_constants.ANY)


def import_as_insecure():
    import sre_constants.ANY as any_str
    safestring.mark_safe(any_str)


def from_import_insecure():
    from sre_constants import ANY
    safestring.mark_safe(ANY)


def from_import_as_insecure():
    from sre_constants import ANY as any_str
    safestring.mark_safe(any_str)


def with_insecure(path):
    with open(path) as f:
        safestring.mark_safe(f.read())


def also_with_insecure(path):
    with open(path) as f:
        safestring.mark_safe(f)


def for_insecure():
    my_secure_str = ''
    for i in range(random.randint(0, 1)):  # nosec
        my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
    safestring.mark_safe(my_secure_str)


def while_insecure():
    my_secure_str = ''
    while ord(os.urandom(1)) % 2 == 0:
        my_secure_str += insecure_function('insecure', cls='" onload="alert(\'xss\')')
    safestring.mark_safe(my_secure_str)


def some_insecure_case():
    if ord(os.urandom(1)) % 2 == 0:
        my_secure_str = insecure_function('insecure', cls='" onload="alert(\'xss\')')
    elif ord(os.urandom(1)) % 2 == 0:
        my_secure_str = 'Secure'
    else:
        my_secure_str = 'Secure'
    safestring.mark_safe(my_secure_str)

mystr = 'insecure'


def test_insecure_shadow():  # var assigned out of scope
    safestring.mark_safe(mystr)


def test_insecure(str_arg):
    safestring.mark_safe(str_arg)


def test_insecure_with_assign(str_arg=None):
    if not str_arg:
        str_arg = 'could be insecure'
    safestring.mark_safe(str_arg)
