# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5

import os
import secrets

from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        # A random per-process key unless one is supplied, so the tutorial's
        # guessable "dev" key is never used; sessions don't survive a restart
        # without THREATINTEL_SECRET_KEY or instance/config.py
        SECRET_KEY=os.environ.get("THREATINTEL_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.path.join(app.instance_path, "threatintel.sqlite"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    if test_config is None:
        # instance/config.py, if present, overrides the defaults (e.g. a real SECRET_KEY)
        app.config.from_pyfile("config.py", silent=True)
    else:
        app.config.from_mapping(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)

    return app
