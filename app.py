
# This file only exists to generate database migrations

from flask import Flask
from flask_migrate import Migrate

from common import db

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

migrate = Migrate()
migrate.init_app(app, db.db, render_as_batch=True)
