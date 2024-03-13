from psycopg2 import sql

table = 'users; drop table users; --'
sql.SQL('select * from {}').format(sql.SQL(table))
