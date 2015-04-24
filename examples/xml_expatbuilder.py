import xml.dom.expatbuilder as bad
import defusedxml.expatbuilder as good

bad.parse('filethatdoesntexist.xml')
good.parse('filethatdoesntexist.xml')

xmlString = "<note>\n<to>Tove</to>\n<from>Jani</from>\n<heading>Reminder</heading>\n<body>Don't forget me this weekend!</body>\n</note>"

bad.parseString(xmlString)
good.parseString(xmlString)
