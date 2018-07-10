
def from_html():
    from django.utils.html import strip_tags
    return strip_tags('&gotcha&#;<>')


def from_defaultfilters():
    from django.template.defaultfilters import strip_tags
    strip_tags('&gotcha&#;<>')
