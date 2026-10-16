# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5

import sqlite3

from flask import Blueprint, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from threatintel.db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")

USERNAME_MAX = 64
PASSWORD_MIN = 8
PASSWORD_MAX = 128


@bp.before_app_request
def load_logged_in_user():
    # A user_id for a deleted user leaves g.user as None (anonymous)
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()


@bp.route("/register", methods=("GET", "POST"))
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        # The password is never stripped: spaces in it are part of it
        password = request.form.get("password", "")
        if not username:
            error = "Username is required."
        elif len(username) > USERNAME_MAX:
            error = f"Username must be at most {USERNAME_MAX} characters."
        elif not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
            error = f"Password must be {PASSWORD_MIN} to {PASSWORD_MAX} characters."
        else:
            db = get_db()
            try:
                with db:
                    db.execute(
                        "INSERT INTO user (username, password) VALUES (?, ?)",
                        (username, generate_password_hash(password)),
                    )
            except sqlite3.IntegrityError:
                error = "That username is already registered."
            else:
                return redirect(url_for("auth.login"))
    return render_template("auth/register.html", error=error)


@bp.route("/login", methods=("GET", "POST"))
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()
        # One message for both cases, so the form doesn't reveal which usernames exist
        if user is None or not check_password_hash(user["password"], password):
            error = "Invalid username or password."
        else:
            # clear() first so nothing planted before login survives into the session
            session.clear()
            session["user_id"] = user["id"]
            # A fixed local path; any ?next= is ignored, so login can't be used
            # as an open redirect
            return redirect("/")
    return render_template("auth/login.html", error=error)


@bp.route("/logout", methods=("POST",))
def logout():
    session.clear()
    return redirect("/")
