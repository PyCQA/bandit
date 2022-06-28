import sqlalchemy

# bad
query = """SELECT *
FROM foo WHERE id = '%s'""" % identifier
query = """INSERT INTO foo
VALUES ('a', 'b', '%s')""" % value
query = """DELETE FROM foo
WHERE id = '%s'""" % identifier
query = """UPDATE foo
SET value = 'b'
WHERE id = '%s'""" % identifier
query = """WITH cte AS (SELECT x FROM foo)
SELECT x FROM cte WHERE x = '%s'""" % identifier
# bad alternate forms
query = """SELECT *
FROM foo
WHERE id = '""" + identifier + "'"
query = """SELECT *
FROM foo
WHERE id = '{}'""".format(identifier)

query = f"""
SELECT *
FROM foo
WHERE id = {identifier}
"""

# bad
cur.execute("""SELECT *
FROM foo
WHERE id = '%s'""" % identifier)
cur.execute("""INSERT INTO foo
VALUES ('a', 'b', '%s')""" % value)
cur.execute("""DELETE FROM foo
WHERE id = '%s'""" % identifier)
cur.execute("""UPDATE foo
SET value = 'b'
WHERE id = '%s'""" % identifier)
# bad alternate forms
cur.execute("""SELECT *
FROM foo
WHERE id = '""" + identifier + "'")
cur.execute("""SELECT *
FROM foo
WHERE id = '{}'""".format(identifier))

# bad with f-string
query = f"""
SELECT *
FROM foo
WHERE id = {identifier}
"""
query = f"""
SELECT *
FROM foo
WHERE id = {identifier}
"""

query = f"""
SELECT *
FROM foo
WHERE id = {identifier}"""
query = f"""
SELECT *
FROM foo
WHERE id = {identifier}"""

cur.execute(f"""
SELECT
    {column_name}
FROM foo
WHERE id = 1""")

cur.execute(f"""
SELECT
    {a + b}
FROM foo
WHERE id = 1""")

cur.execute(f"""
INSERT INTO
    {table_name}
VALUES (1)""")
cur.execute(f"""
UPDATE {table_name}
SET id = 1""")

# implicit concatenation mixed with f-strings
cur.execute("SELECT "
            f"{column_name} "
            "FROM foo "
            "WHERE id = 1"
            )
cur.execute("INSERT INTO "
            f"{table_name} "
            "VALUES (1)")
cur.execute(f"UPDATE {table_name} "
            "SET id = 1")

# good
cur.execute("""SELECT *
FROM foo
WHERE id = '%s'""", identifier)
cur.execute("""INSERT INTO foo
VALUES ('a', 'b', '%s')""", value)
cur.execute("""DELETE FROM foo
WHERE id = '%s'""", identifier)
cur.execute("""UPDATE foo
SET value = 'b'
WHERE id = '%s'""", identifier)


# bug: https://bugs.launchpad.net/bandit/+bug/1479625
def a():
    def b():
        pass

    return b


a()("""SELECT %s
FROM foo""" % val)

# skip
query = """SELECT *
FROM foo WHERE id = '%s'""" % identifier  # nosec
query = """SELECT *
FROM foo WHERE id = '%s'""" % identifier  # nosec B608
query = """
SELECT *
FROM foo
WHERE id = '%s'
""" % identifier  # nosec B608

query = f"""
SELECT *
FROM foo
WHERE id = {identifier}
"""  # nosec
query = f"""
SELECT *
FROM foo
WHERE id = {identifier}
"""  # nosec B608

query = f"""
SELECT *
FROM foo
WHERE id = {identifier}"""  # nosec
query = f"""
SELECT *
FROM foo
WHERE id = {identifier}"""  # nosec B608

cur.execute("SELECT * "  # nosec
            "FROM foo "
            f"WHERE id = {identifier}")
cur.execute("SELECT * "  # nosec B608
            "FROM foo "
            f"WHERE id = {identifier}")

query = ("SELECT * "  # nosec
         "FROM foo "
         f"WHERE id = {identifier}")
query = ("SELECT * "  # nosec B608
         "FROM foo "
         f"WHERE id = {identifier}")

# nosec is not recognized for the 4 below cases in python 3.7
query = ("SELECT * "
         "FROM foo "  # nosec
         f"WHERE id = {identifier}")
query = ("SELECT * "
         "FROM foo "  # nosec B608
         f"WHERE id = {identifier}")
query = ("SELECT * "
         "FROM foo "
         f"WHERE id = {identifier}")  # nosec
query = ("SELECT * "
         "FROM foo "
         f"WHERE id = {identifier}")  # nosec B608
