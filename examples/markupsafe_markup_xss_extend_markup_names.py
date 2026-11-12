from markupsafe import Markup
from webhelpers.html import literal

content = "<script>alert('Hello, world!')</script>"
Markup(f"unsafe {content}")
literal(f"unsafe {content}")


class CustomLiteral(literal):
    pass


CustomLiteral(f"unsafe {content}")
