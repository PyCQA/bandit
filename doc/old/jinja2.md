jinja2 templates
=====================
From the doc page, 'Jinja2 is a modern and designer-friendly templating language
for Python." Jinja2 is the templating engine used in the common web framework
Flask.

The [Jinja2 docs](http://jinja.pocoo.org/docs/dev/api/#autoescaping) on
autoescaping indirectly state that the default behavior is autoescape=False:
    "As of Jinja 2.4 the preferred way to do autoescaping is to **enable** the
    Autoescape Extension and to configure a sensible default for autoescaping."

### Incorrect
With autoescape=False, the default behavior, we can see XSS is trivial if a user
controlled value is ever rendered in a jinja2 template:
```shell
>>> from jinja2 import Template
>>> t = Template("Hello darkness, my old {{ friend }}")
>>> t.render(friend="friend")
    u'Hello darkness, my old friend'
>>> t.render(friend="<h1>enemy</h1>")
    u'Hello darkness, my old <h1>enemy</h1>'
```

### Correct
The correct solution is to use autoescape=True, as we can see below:
```shell
>>> from jinja2 import Template
>>> t = Template("Hello darkness, my old {{ friend }}", autoescape=True)
>>> t.render(friend="friend")
    u'Hello darkness, my old friend'
>>> t.render(friend="<h1>enemy</h1>")
    u'Hello darkness, my old &lt;h1&gt;enemy&lt;/h1&gt;'
>>>
```

## Consequences
* HTML/Javascript injection, known as XSS attacks.

## References
* https://realpython.com/blog/python/primer-on-jinja-templating/
* http://jinja.pocoo.org/docs/dev/api/#autoescaping
