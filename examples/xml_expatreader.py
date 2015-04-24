import xml.sax.expatreader as bad
import defusedxml.expatreader as good

p = bad.create_parser()
b = good.create_parser()
