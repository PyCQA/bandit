import jinja2
from jinja2 import Environment, select_autoescape
templateLoader = jinja2.FileSystemLoader( searchpath="/" )
something = ''

Environment(loader=templateLoader, load=templateLoader, autoescape=True)
templateEnv = jinja2.Environment(autoescape=True,
        loader=templateLoader )
Environment(loader=templateLoader, load=templateLoader, autoescape=something)
templateEnv = jinja2.Environment(autoescape=False, loader=templateLoader )
Environment(loader=templateLoader,
            load=templateLoader,
            autoescape=False)

Environment(loader=templateLoader,
            load=templateLoader)

Environment(loader=templateLoader, autoescape=select_autoescape())

Environment(loader=templateLoader,
            autoescape=select_autoescape(['html', 'htm', 'xml']))

Environment(loader=templateLoader,
            autoescape=jinja2.select_autoescape(['html', 'htm', 'xml']))


def fake_func():
    return 'foobar'
Environment(loader=templateLoader, autoescape=fake_func())


# Test cases for dynamic template source (B701)
from jinja2 import Template
from jinja2 import Environment
from jinja2.sandbox import SandboxedEnvironment

def dangerous_template_source(user_input):
    # Should trigger B701 - non-literal template source
    return Template(user_input).render()

def dangerous_from_string(user_input):
    # Should trigger B701 - non-literal template source
    env = Environment()
    return env.from_string(user_input).render()

def safe_sandboxed_from_string(user_input):
    # Should NOT trigger - SandboxedEnvironment is safe
    env = SandboxedEnvironment()
    return env.from_string(user_input).render()

def safe_literal_template():
    # Should NOT trigger - literal template source
    return Template("Hello {{ name }}").render(name="World")
