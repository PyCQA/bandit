
def from_http(url):
    from django.utils.http import is_safe_url
    return is_safe_url(url)


def from_comments(url):
    from django.contrib.comments.views.utils import is_safe_url
    return is_safe_url(url)


def from_auth(url):
    from django.contrib.auth.views import is_safe_url
    return is_safe_url(url)


def from_i18n(url):
    from django.views.i18n import is_safe_url
    return is_safe_url(url)
