
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
session = db.session


class ApplicationFlags:
	SERVICE_CLOSED = 1
	SYSTEM_TITLE = 2
	ALLOW_NO_CERT = 4


class Application(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	service_closed = db.Column(db.Boolean, nullable=False, default=False)
	allow_no_cert = db.Column(db.Boolean, nullable=False, default=False)
	system_title = db.Column(db.Boolean, nullable=False, default=False)
	application_id = db.Column(db.String, unique=True, nullable=False)
	application_version = db.Column(db.Integer, nullable=False)
	online_play_policy = db.Column(db.Enum("MEMBERSHIP_REQUIRED", "FREE"), nullable=False)
	policy_handler = db.Column(db.Enum("SYSTEM", "GAME_SERVER"), nullable=False)
	name = db.Column(db.String)


class Ban(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	rom_id = db.Column(db.String, nullable=False)
	start = db.Column(db.DateTime)
	end = db.Column(db.DateTime)
	reason = db.Column(db.String)


def init_app(app):
	db.init_app(app)
