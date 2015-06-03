import xml.sax
from xml import sax
import defusedxml.sax

class ExampleContentHandler(xml.sax.ContentHandler):
    def __init__(self):
        xml.sax.ContentHandler.__init__(self)

    def startElement(self, name, attrs):
        print('start:', name)

    def endElement(self, name):
        print('end:', name)

    def characters(self, content):
        print('chars:', content)

def main():
    xmlString = "<note>\n<to>Tove</to>\n<from>Jani</from>\n<heading>Reminder</heading>\n<body>Don't forget me this weekend!</body>\n</note>"
    # bad
    xml.sax.parseString(xmlString, ExampleContentHandler())
    xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())
    sax.parseString(xmlString, ExampleContentHandler())
    sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler)

    # good
    defusedxml.sax.parseString(xmlString, ExampleContentHandler())

    # bad
    xml.sax.make_parser()
    sax.make_parser()
    print('nothing')
    # good
    defusedxml.sax.make_parser()

if __name__ == "__main__":
    main()
