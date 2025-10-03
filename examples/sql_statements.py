import sqlalchemy

# bad
query = "SELECT * FROM foo WHERE id = '%s'" % identifier
query = "INSERT INTO foo VALUES ('a', 'b', '%s')" % value
query = "DELETE FROM foo WHERE id = '%s'" % identifier
query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
query = """WITH cte AS (SELECT x FROM foo)
SELECT x FROM cte WHERE x = '%s'""" % identifier
# bad alternate forms
query = "SELECT * FROM foo WHERE id = '" + identifier + "'"
query = "SELECT * FROM foo WHERE id = '{}'".format(identifier)
query = "SELECT * FROM foo WHERE id = '[VALUE]'".replace("[VALUE]", identifier)

# bad
cur.execute("SELECT * FROM foo WHERE id = '%s'" % identifier)
cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')" % value)
cur.execute("DELETE FROM foo WHERE id = '%s'" % identifier)
cur.execute("UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier)
# bad alternate forms
cur.execute("SELECT * FROM foo WHERE id = '" + identifier + "'")
cur.execute("SELECT * FROM foo WHERE id = '{}'".format(identifier))
cur.execute("SELECT * FROM foo WHERE id = '[VALUE]'".replace("[VALUE]", identifier))

# bad f-strings
cur.execute(f"SELECT {column_name} FROM foo WHERE id = 1")
cur.execute(f"SELECT {a + b} FROM foo WHERE id = 1")
cur.execute(f"INSERT INTO {table_name} VALUES (1)")
cur.execute(f"UPDATE {table_name} SET id = 1")

# good
cur.execute("SELECT * FROM foo WHERE id = '%s'", identifier)
cur.execute("INSERT INTO foo VALUES ('a', 'b', '%s')", value)
cur.execute("DELETE FROM foo WHERE id = '%s'", identifier)
cur.execute("UPDATE foo SET value = 'b' WHERE id = '%s'", identifier)

# bug: https://bugs.launchpad.net/bandit/+bug/1479625
def a():
    def b():
        pass
    return b

a()("SELECT %s FROM foo" % val)

# real world false positives
choices=[('server_list', _("Select from active instances"))]
print("delete from the cache as the first argument")

# good - parameterized queries with named parameters (issue #1302)
# These should NOT trigger warnings even though table names are dynamic
# SQL databases don't support parameterized table/column names
table = 'users'
query = f"SELECT * FROM {table} WHERE id = :id"
query = f"DELETE FROM {table} WHERE user_id = :user_id"
query = f"UPDATE {table} SET status = :status WHERE id = :id"
query = f"INSERT INTO {table} (name, email) VALUES (:name, :email)"

# good - parameterized with question marks
query = f"SELECT * FROM {table} WHERE id = ?"
query = f"DELETE FROM {table} WHERE user_id = ?"
query = f"UPDATE {table} SET status = ? WHERE id = ?"

# good - parameterized with numbered parameters (PostgreSQL style)
query = f"SELECT * FROM {table} WHERE id = $1"
query = f"DELETE FROM {table} WHERE user_id = $1 AND status = $2"
query = f"UPDATE {table} SET status = $1 WHERE id = $2"

# good - cursor.execute with parameterized queries
cur.execute(f"SELECT * FROM {table} WHERE id = :id", {'id': 123})
cur.execute(f"DELETE FROM {table} WHERE user_id = :user_id", {'user_id': 456})
cur.execute(f"UPDATE {table} SET status = :status WHERE id = :id", 
            {'status': 'active', 'id': 789})

# good - mixed dynamic table and multiple parameters
cur.execute(f"""
    DELETE FROM {table} 
    WHERE user_id = :user_id 
    AND created_date < :date
""", {'user_id': user_id, 'date': cutoff_date})

# good - question mark parameterization with execute
cur.execute(f"SELECT * FROM {table} WHERE id = ? AND status = ?", (123, 'active'))
