#!/usr/bin/env python3

# from flask import Flask, render_template, request, redirect, url_for, Response
import flask
from flask import request
import argparse
import crypt
import getpass
import hashlib
import os
import random
import sys
import time

LOGINS_FILE = "proxylogins"
COOKIE = "magicproxyauth"
AUTHFORM = "authform.html"
LOGINS = {}
authdcookies = set()


app = flask.Flask(__name__)


@app.route("/", defaults={"path": ""}, methods=["GET"])
@app.route("/<path:path>", methods=["GET"])
def index(path):
    authcookie = getauthcookie()
    if authcookie in authdcookies:
        return "Auth"

    resp = flask.make_response(flask.render_template("authform.jinja"))
    if authcookie is None:
        authcookie = gencookie()
        resp.set_cookie(
            COOKIE,
            authcookie,
            domain=COOKIE_DOMAIN,
            max_age=2147483647,
            secure=COOKIE_SECURE,
        )
    return resp, 401


@app.route("/", defaults={"path": ""}, methods=["POST"])
@app.route("/<path:path>", methods=["POST"])
def submit(**path):
    username = request.headers.get("X-set-username")
    password = request.headers.get("X-set-password")
    authvalue = getauthcookie()

    if authvalue and checklogin(username, password):
        authdcookies.add(authvalue)
        return "location.reload();", 401
    else:
        time.sleep(1)
        return "alert('Wrong username/password or cookie not set');", 401


def getauthcookie():
    authvalue = request.cookies.get(COOKIE)
    if authvalue:
        if len(authvalue) != 128:
            authvalue = None
    return authvalue


def gencookie():
    i = str(random.getrandbits(100000))
    return hashlib.sha512(i.encode()).hexdigest()


def loadlogins(ignoreerrors=False):
    try:
        f = open(LOGINS_FILE)
    except Exception as e:
        if not ignoreerrors:
            print(("Error loading password file: {}".format(e)))
        return

    for line in f:
        line = line.strip()
        parts = line.split()
        if len(parts) != 2:
            continue

        username, password = parts
        if len(username) < 3 or len(password) < 3:
            continue

        LOGINS[username.lower()] = password


def checklogin(username, password):
    if username.lower() in LOGINS:
        if LOGINS[username] == crypt.crypt(password, LOGINS[username]):
            return True
    return False


def addlogin(username, password):
    loadlogins(ignoreerrors=True)
    LOGINS[username.lower()] = crypt.crypt(password, crypt.mksalt())
    f = open(LOGINS_FILE, "w")
    for user, password in LOGINS.items():
        f.write("{}\t{}\n".format(user, password))
    f.close()


def main():
    global COOKIE_DOMAIN, COOKIE_SECURE
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--domain",
        help="Domain to use when setting the cookie, ideally your root domain. "
        'This can also be set using the "DOMAIN" environment variable.',
    )
    parser.add_argument("-p", "--port", type=int, help="Port to listen on, default 80")
    parser.add_argument("-a", "--adduser", action="store_true")
    parser.add_argument(
        "--nosecure",
        action="store_true",
        help="Do NOT set the secure flag on the cookie, used for development.",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Run flask in debug mode for development."
    )
    args = parser.parse_args()
    if not args.domain:
        if os.environ.get("DOMAIN"):
            args.domain = os.environ["DOMAIN"]
    if not args.port:
        if os.environ.get("PORT"):
            args.port = int(os.environ["PORT"])
        else:
            args.port = 80
    if args.nosecure:
        COOKIE_SECURE = False
    else:
        COOKIE_SECURE = True
    if args.adduser:
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        addlogin(username, password)
    elif args.domain:
        COOKIE_DOMAIN = args.domain
        loadlogins()
        app.run(host="0.0.0.0", port=args.port, debug=args.debug)
    else:
        print("Either -d or -a must be supplied or environment set!")
        sys.exit(1)


if __name__ == "__main__":
    main()
