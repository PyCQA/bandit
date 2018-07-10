
def valid_formats():
    from django.utils.formats import get_format
    return get_format('DATE_FORMAT')


def args_formats(DATE_FORMAT):
    from django.utils.formats import get_format
    return get_format(DATE_FORMAT)


def var_formats():
    from django.utils.formats import get_format
    DATE_FORMAT = 'SECRET_KEY'
    return get_format(DATE_FORMAT)


def from_formats():
    from django.utils.formats import get_format
    return get_format('SECRET_KEY')


def from_i18n():
    from django.views.i18n import get_format
    return get_format('SECRET_KEY')


def from_widgets():
    from django.forms.extras.widgets import get_format
    return get_format('SECRET_KEY')
