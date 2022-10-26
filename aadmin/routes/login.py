
from flask import Blueprint, flash, redirect, render_template, request, session
import os


bp = Blueprint("login", __name__)


@bp.route("/")
def index():
	return redirect("/admin")

@bp.route("/login", methods=["GET", "POST"])
def login():
	if request.method == "POST":
		username = request.form.get("username", "")
		password = request.form.get("password", "")
		if username == os.environ["USERNAME"] and password == os.environ["PASSWORD"]:
			session["admin"] = True
			return redirect("/admin")
		flash("Wrong username or password.")
	return render_template("login.html")

@bp.route("/logout")
def logout():
	session.clear()
	return redirect("/login")
