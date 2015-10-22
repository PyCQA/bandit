hardcoded_sql_expressions
=========================

Description
-----------
An SQL injection attack consists of insertion or "injection" of a SQL query via
the input data given to an application. It is a very common attack vector. This
plugin test looks for strings that resemble SQL statements that are involved in
some form of string building operation. For example:

 - "SELECT %s FROM derp;" % var
 - "SELECT thing FROM " + tab
 - "SELECT " + val + " FROM " + tab + ...

Unless care is taken to sanitize and control the input data when building such
SQL statement strings, an injection attack becomes possible. If strings of this
nature are discovered, a LOW confidence issue is reported. In order to boost
result confidence, this plugin test will also check to see if the discovered
string is in use with standard Python DBAPI calls `execute` or `executemany`.
If so, a MEDIUM issue is reported. For example:

 - cursor.execute("SELECT %s FROM derp;" % var)


Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
None


Sample Output
-------------
.. code-block:: none

    >> Issue: Possible SQL injection vector through string-based query construction.
       Severity: Medium   Confidence: Low
       Location: ./examples/sql_statements_without_sql_alchemy.py:4
    3 query = "DELETE FROM foo WHERE id = '%s'" % identifier
    4 query = "UPDATE foo SET value = 'b' WHERE id = '%s'" % identifier
    5

References
----------
- https://www.owasp.org/index.php/SQL_Injection
- https://security.openstack.org/guidelines/dg_parameterize-database-queries.html
