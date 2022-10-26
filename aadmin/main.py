
from flask import Flask
from routes import admin, certificates, login
from common import db
import os


def create_app():
	app = Flask(__name__)
	app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
	app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
	app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
	
	app.register_blueprint(login.bp)
	app.register_blueprint(certificates.bp)
	
	db.init_app(app)
	admin.init_app(app)
	return app
