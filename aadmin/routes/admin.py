
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
from flask_admin import Admin, AdminIndexView
from flask import redirect, session
from common import db


class IndexView(AdminIndexView):
	def is_visible(self):
		return False
	
	def is_accessible(self):
		return "admin" in session
	
	def inaccessible_callback(self, name):
		return redirect("/login")


def init_app(app):
	admin = Admin(app, name="AAdmin", index_view=IndexView())
	admin.add_link(MenuLink("Logout", "/logout"))
	admin.add_view(ModelView(db.Application, db.session, "Applications"))
	admin.add_view(ModelView(db.Ban, db.session, "Bans"))
