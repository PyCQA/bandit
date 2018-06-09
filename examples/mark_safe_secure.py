import os
from django.utils import safestring

safestring.mark_safe('<b>secure</b>')
safestring.SafeText('<b>secure</b>')
safestring.SafeUnicode('<b>secure</b>')
safestring.SafeString('<b>secure</b>')
safestring.SafeBytes('<b>secure</b>')

my_secure_str = '<b>Hello World</b>'
safestring.mark_safe(my_secure_str)

my_secure_str, _ = ('<b>Hello World</b>', '')
safestring.mark_safe(my_secure_str)

also_secure_str = my_secure_str
safestring.mark_safe(also_secure_str)


def try_secure():
    try:
        my_secure_str = 'Secure'
    except Exception:
        my_secure_str = 'Secure'
    else:
        my_secure_str = 'Secure'
    finally:
        my_secure_str = 'Secure'
    safestring.mark_safe(my_secure_str)


def format_secure():
    safestring.mark_safe('<b>{}</b>'.format('secure'))
    my_secure_str = 'secure'
    safestring.mark_safe('<b>{}</b>'.format(my_secure_str))
    safestring.mark_safe('<b>{} {}</b>'.format(my_secure_str, 'a'))
    safestring.mark_safe('<b>{} {}</b>'.format(*[my_secure_str, 'a']))
    safestring.mark_safe('<b>{b}</b>'.format(b=my_secure_str))  # nosec TODO
    safestring.mark_safe('<b>{b}</b>'.format(**{'b': my_secure_str}))  # nosec TODO
    my_secure_str = '<b>{}</b>'.format(my_secure_str)
    safestring.mark_safe(my_secure_str)


def percent_secure():
    safestring.mark_safe('<b>%s</b>' % 'secure')
    my_secure_str = 'secure'
    safestring.mark_safe('<b>%s</b>' % my_secure_str)
    safestring.mark_safe('<b>%s %s</b>' % (my_secure_str, 'a'))
    safestring.mark_safe('<b>%(b)s</b>' % {'b': my_secure_str})  # nosec TODO


def with_secure(path):
    with open(path) as f:
        safestring.mark_safe('Secure')


def loop_secure():
    my_secure_str = ''

    for i in range(ord(os.urandom(1))):
        my_secure_str += ' Secure'
    safestring.mark_safe(my_secure_str)
    while ord(os.urandom(1)) % 2 == 0:
        my_secure_str += ' Secure'
    safestring.mark_safe(my_secure_str)


def all_secure_case():
    if ord(os.urandom(1)) % 2 == 0:
        my_secure_str = 'Secure'
    elif ord(os.urandom(1)) % 2 == 0:
        my_secure_str = 'Secure'
    else:
        my_secure_str = 'Secure'
    safestring.mark_safe(my_secure_str)
