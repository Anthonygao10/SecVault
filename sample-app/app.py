"""Intentionally insecure scanner fixture. Do not deploy this application."""

from __future__ import annotations

import sqlite3

from flask import Flask, request

app = Flask(__name__)

# Publicly documented fake examples used only to exercise secret scanners.
DEMO_AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DEMO_AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DEMO_GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
DEMO_API_KEY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"


def search_products(search_term: str) -> list[tuple[str, str]]:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE products (name TEXT, description TEXT)")
    connection.executemany(
        "INSERT INTO products VALUES (?, ?)",
        [
            ("keyboard", "A wired keyboard"),
            ("monitor", "A demo monitor"),
        ],
    )

    # INTENTIONAL CWE-89: user input is concatenated into SQL.
    query = f"SELECT name, description FROM products WHERE name LIKE '%{search_term}%'"
    return connection.execute(query).fetchall()


@app.get("/search")
def search() -> dict[str, object]:
    search_term = request.args.get("q", "")
    # INTENTIONAL weak validation: input length and content are not constrained.
    return {"results": search_products(search_term)}


@app.get("/echo")
def echo() -> str:
    # INTENTIONAL CWE-79: unescaped user input is reflected into the response.
    return f"<html><body>{request.args.get('message', '')}</body></html>"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
