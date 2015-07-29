Use safe XML libraries to avoid XML vulnerabilities
=====================
XML vulnerabilities are known and well studied. The [defusedxml](https://pypi.python.org/pypi/defusedxml/) library provides a great synposis of XML vulnerabilities, how they're exploited, and which Python libraries are vulnerable to which attacks.

Most XML vulnerabilities essentially amount to Denial of Service attacks but as [previous blackhat presentations](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf) have shown, XML vulnerabilities can lead to local file reading, intranet access, and some times remote code execution.

We don't attempt to rehash the details of each vulnerability class and instead recommend those interested read [defuxedxml](https://pypi.python.org/pypi/defusedxml/)'s page, including references.

### Incorrect
Currently, the following Python XML libraries are vulnerable to some form of XML attack:
* [xml.sax](https://docs.python.org/2/library/xml.sax.html)
  - vulnerable to: billion laughs, quadratic blowup, external entity expansion, DTD retrieval
* [xml.etree.ElementTree](https://docs.python.org/2/library/xml.etree.elementtree.html)
  - vulnerable to: billion laughs, quadratic blowup
* [xml.dom.minidom](https://docs.python.org/2/library/xml.dom.minidom.html)
  - vulnerable to: billion laughs, quadratic blowup
* [xml.dom.pulldom](https://docs.python.org/2/library/xml.dom.pulldom.html)
  - vulnerable to: billion laughs, quadratic blowup, external entity expansion, DTD retrieval
* [xmlrpclib](https://docs.python.org/2/library/xmlrpclib.html)
  - vulnerable to: billion laughs, quadratic blowup, decompression bomb

[Python's XML library page](https://docs.python.org/2/library/xml.html#xml-vulnerabilities) indicates that [defusedxml](https://pypi.python.org/pypi/defusedxml/) is the correct choice for XML libraries.

### Correct
#### xml.sax
Replace all xml.sax parsers with defusedxml parsers:
* ```xml.sax.parser()``` -> ```defusedxml.sax.parser()```
* ```xml.sax.parseString()``` -> ```defusedxml.sax.parseString()```
* ```xml.sax.create_parser()``` -> ```defusedxml.sax.parseString()```

Intead of this:
```python
    import xml.sax

    class ExampleContentHandler(xml.sax.ContentHandler):
        def __init__(self):
            xml.sax.ContentHandler.__init__(self)

        def startElement(self, name, attrs):
            print 'start:', name

        def endElement(self, name):
            print 'end:', name

        def characters(self, content):
            print 'chars:', content

    def main():
       xml.sax.parse(open('input.xml'), ExampleContentHandler())

    if __name__ == "__main__":
        main()
```

Do this:
```python
    import xml.sax
    import defusedxml.sax

    class ExampleContentHandler(xml.sax.ContentHandler):
        def __init__(self):
            xml.sax.ContentHandler.__init__(self)

        def startElement(self, name, attrs):
            print 'start:', name

        def endElement(self, name):
            print 'end:', name

        def characters(self, content):
            print 'chars:', content

    def main():
       defusedxml.sax.parse(open('input.xml'), ExampleContentHandler())

    if __name__ == "__main__":
        main()
```

#### xml.etree.ElementTree
Replace the following instances of xml.etree.ElementTree functions with the corresponding defusedxml functions:
* ```xml.etree.ElementTree.parse()``` -> ```defusedxml.ElementTree.parse()```
* ```xml.etree.ElementTree.iterparse()``` -> ```defusedxml.ElementTree.iterparse()```
* ```xml.etree.ElementTree.fromstring()``` -> ```defusedxml.ElementTree.fromstring()```
* ```xml.etree.ElementTree.XMLParser``` -> ```defusedxml.ElementTree.XMLParser```

Intead of this:
```python
    import xml.etree.ElementTree as ET
    tree = ET.parse("input.xml")
    root = tree.getroot()
```

Do this:
```python
    import defusedxml.ElementTree as ET
    tree = ET.parse("input.xml")
    root = tree.getroot()
```

#### xml.etree.cElementTree
Replace the following instances of xml.etree.cElementTree functions with the corresponding defusedxml functions:
* ```xml.etree.cElementTree.parse()``` -> ```defusedxml.cElementTree.parse()```
* ```xml.etree.cElementTree.iterparse()``` -> ```defusedxml.cElementTree.iterparse()```
* ```xml.etree.cElementTree.fromstring()``` -> ```defusedxml.cElementTree.fromstring()```
* ```xml.etree.cElementTree.XMLParser``` -> ```defusedxml.cElementTree.XMLParser```

Intead of this:
```python
    import xml.etree.cElementTree as ET
    tree = ET.parse("input.xml")
    root = tree.getroot()
```

Do this:
```python
    import defusedxml.cElementTree as ET
    tree = ET.parse("input.xml")
    root = tree.getroot()
```

#### xml.dom.minidom
Replace the following instances of xml.dom.minidom functions with the corresponding defusedxml functions:
* ```xml.dom.minidom.parse()``` -> ```defusedxml.minidom.parse()```
* ```xml.dom.minidom.parseString()``` -> ```defusedxml.minidom.parseString()```

Intead of this:
```python
    from xml.dom.minidom import parseString
    parseString('<myxml>Some data<empty/> some more data</myxml>')
```

Do this:
```python
    from defusedxml.minidom import parseString
    parseString('<myxml>Some data<empty/> some more data</myxml>')
```

#### xml.dom.pulldom
Replace the following instances of xml.dom.pulldom functions with the corresponding defusedxml functions:
* ```xml.dom.pulldom.parse()``` -> ```defusedxml.pulldom.parse()```
* ```xml.dom.pulldom.parseString()``` -> ```defusedxml.pulldom.parseString()```

Intead of this:
```python
    from xml.dom.pulldom import parseString
    parseString('<myxml>Some data<empty/> some more data</myxml>')
```

Do this:
```python
    from defusedxml.pulldom import parseString
    parseString('<myxml>Some data<empty/> some more data</myxml>')
```

#### xmlrpclib
Taken directly from the defusedxml page:
"The function monkey_patch() enables the fixes, unmonkey_patch() removes the patch and puts the code in its former state."

Intead of this:
```python
    from xmlrpclib import ServerProxy, Error

    server = ServerProxy("http://betty.userland.com")

    print server

    try:
        print server.examples.getStateName(41)
    except Error as v:
        print "ERROR", v
```

Do this:
```python
    from xmlrpclib import ServerProxy, Error
    import defusedxml.xmlrpc

    defusedxml.xmlrpc.monkey_patch()

    server = ServerProxy("http://betty.userland.com")

    print server

    try:
        print server.examples.getStateName(41)
    except Error as v:
        print "ERROR", v
```

#### lxml.etree
Replace the following instances of lxml functions with the corresponding defusedxml functions:
* ```lxml.etree.parse()``` -> ```defusedxml.lxml.parse```
* ```lxml.etree.fromstring()``` -> ```defusedxml.lxml.fromstring()```
* ```lxml.etree.RestrictedElement()``` -> ```defusedxml.lxml.RestrictedElement()```
* ```lxml.etree.getDefaultParser()``` -> ```defusedxml.lxml.getDefaultParser()```
* ```lxml.etree.check_docinfo()``` -> ```defusedxml.lxml.check_docinfo()```

Intead of this:
```python
    from lxml import etree
    root = etree.parse('input.xml')
```

Do this:
```python
    from defusedxml.lxml import parse
    root = parse('input.xml')

```
## References
* https://pypi.python.org/pypi/defusedxml/
* https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf
* https://docs.python.org/2/library/xml.sax.html
* https://docs.python.org/2/library/xml.etree.elementtree.html
* https://docs.python.org/2/library/xml.dom.minidom.html
* https://docs.python.org/2/library/xml.dom.pulldom.html
* https://docs.python.org/2/library/xmlrpclib.html
* https://docs.python.org/2/library/xml.html#xml-vulnerabilities
