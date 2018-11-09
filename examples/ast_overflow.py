import ast
import dbm.dumb


ast.literal_eval('x = 2 + 2')

ast.parse('x = 2 + 2')

compile('2 + 2', '?', 'eval')

dbm.dumb.open('test.db')
