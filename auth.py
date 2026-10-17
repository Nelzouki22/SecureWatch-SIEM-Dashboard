from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User
import audit_logger

bp = Blueprint("auth", __name__)

@bp.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated: return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        u = User.query.filter_by(username=request.form.get("username","").strip()).first()
        if u and u.check_password(request.form.get("password","")):
            session.permanent = True
            login_user(u, remember=bool(request.form.get("remember")))
            u.last_login = __import__("datetime").datetime.utcnow()
            db.session.commit()
            audit_logger.record("LOGIN", f"user {u.username} logged in", ip=request.remote_addr)
            return redirect(request.args.get("next") or url_for("dashboard.index"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html", mode="login")

@bp.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        email = request.form.get("email","").strip()
        pw = request.form.get("password","")
        if not username or not email or len(pw) < 8:
            flash("Username, email and password of at least 8 chars are required.","danger")
            return render_template("login.html", mode="register")
        if User.query.filter((User.username==username)|(User.email==email)).first():
            flash("Username or email already exists.","danger")
            return render_template("login.html", mode="register")
        u = User(username=username, email=email, role="analyst")
        u.set_password(pw); db.session.add(u); db.session.commit()
        audit_logger.record("REGISTER", f"new user {username}")
        flash("Account created. Please log in.","success")
        return redirect(url_for("auth.login"))
    return render_template("login.html", mode="register")

@bp.route("/logout")
@login_required
def logout():
    audit_logger.record("LOGOUT", f"user {current_user.username} logged out", ip=request.remote_addr)
    logout_user(); return redirect(url_for("auth.login"))