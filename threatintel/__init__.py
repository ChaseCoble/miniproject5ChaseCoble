# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5

import os

from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY="dev",
        DATABASE=os.path.join(app.instance_path, "threatintel.sqlite"),
    )

    if test_config is None:
        # instance/config.py, if present, overrides the defaults (e.g. a real SECRET_KEY)
        app.config.from_pyfile("config.py", silent=True)
    else:
        app.config.from_mapping(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    from . import db
    db.init_app(app)

    return app
