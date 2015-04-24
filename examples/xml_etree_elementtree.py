import xml.etree.ElementTree as badET
import defusedxml.ElementTree as goodET

xmlString = "<note>\n<to>Tove</to>\n<from>Jani</from>\n<heading>Reminder</heading>\n<body>Don't forget me this weekend!</body>\n</note>"

# unsafe
tree = badET.fromstring(xmlString)
print tree
badET.parse('filethatdoesntexist.xml')
badET.iterparse('filethatdoesntexist.xml')
a = badET.XMLParser()

# safe
tree = goodET.fromstring(xmlString)
print tree
goodET.parse('filethatdoesntexist.xml')
goodET.iterparse('filethatdoesntexist.xml')
a = goodET.XMLParser()
