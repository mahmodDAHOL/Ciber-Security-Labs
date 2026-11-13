#!/usr/bin/env python3
"""Northwind internal tools API — DELIBERATELY INSECURE (Lab 11 DevSecOps target).
This file is meant to be *scanned*, not run. Do not copy these patterns."""
import os
import subprocess
import pickle
import hashlib
import sqlite3
import base64
import yaml
import requests
from flask import Flask, request

app = Flask(__name__)

# Hardcoded secret in source (SAST: hardcoded credential) -- replaced at container start
AWS_SECRET_ACCESS_KEY = "__CODE_SECRET__"
DB_PASSWORD = "admin"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # OS command injection: user input in a shell command
    return os.popen("ping -c 1 " + host).read()


@app.route("/exec")
def run_cmd():
    cmd = request.args.get("cmd", "")
    # command injection via subprocess with shell=True
    return subprocess.check_output(cmd, shell=True)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    # code injection via eval()
    return str(eval(expr))


@app.route("/load")
def load_obj():
    data = request.args.get("data", "")
    # insecure deserialization (pickle) -> remote code execution
    obj = pickle.loads(base64.b64decode(data))
    return str(obj)


@app.route("/config")
def load_config():
    blob = request.args.get("yaml", "{}")
    # unsafe YAML load -> code execution
    return str(yaml.load(blob))


@app.route("/user")
def get_user():
    uid = request.args.get("id", "1")
    con = sqlite3.connect("/tmp/app.db")
    # SQL injection via string formatting
    return str(con.execute("SELECT * FROM users WHERE id = %s" % uid).fetchall())


def hash_password(pw):
    # weak hashing algorithm for passwords
    return hashlib.md5(pw.encode()).hexdigest()


def fetch(url):
    # TLS verification disabled
    return requests.get(url, verify=False).text


if __name__ == "__main__":
    # binds all interfaces + debug on in "prod"
    app.run(host="0.0.0.0", debug=True)
