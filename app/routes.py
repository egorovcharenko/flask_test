from functools import wraps

from flask import render_template, flash, redirect, url_for, jsonify, request
from flask_login import current_user, login_user, logout_user, login_required

from app import app, db
from app.forms import LoginForm, AddUserForm
from app.models import User, UserPermissions


# admin rights decorator
def admin_rights_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.permissions == UserPermissions.ADMIN:
            return f(*args, **kwargs)
        else:
            return jsonify({"error": "true", "errorMessage": "Insufficient privileges"}), 403

    return wrapper


# HTML
@app.route('/user', methods=['GET'])
@login_required
def users():
    form = AddUserForm()
    return render_template("users_list.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('users'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user or not user.check_password(form.password.data):
            flash("Invalid credentials")
            return redirect(url_for('login'))
        login_user(user, remember=True)
        return redirect(url_for('users'))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('users'))


# REST endpoints
@app.route('/users', methods=['GET'])
@login_required
def users_get():
    result = []
    for user in User.query.all():
        result.append({
            'id': user.id,
            'username': user.username,
            'permissions': user.permissions
        })
    return jsonify({'users': result})


@app.route('/user', methods=['POST'])
@login_required
@admin_rights_required
def add_user():
    form = AddUserForm()
    if form.validate_on_submit():
        if form.permissions.data:
            permissions = UserPermissions.ADMIN
        else:
            permissions = UserPermissions.REGULAR_USER
        user = User(username=form.username.data, password=form.password.data, permissions=permissions)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('users'))


@app.route('/user/<id>', methods=['DELETE'])
@login_required
@admin_rights_required
def delete_user(id):
    user = User.query.get(id)
    if user:
        if current_user.id == int(id):
            return jsonify({'success': 'false', 'errorMessage': 'cannot delete current user'}), 400
        else:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'success': 'true'})
    else:
        return jsonify({'success': 'false', 'errorMessage': 'user not found'}), 400


@app.route('/user/<id>', methods=['PATCH'])
@login_required
@admin_rights_required
def update_user(id):
    user = User.query.get(id)
    if user:
        data = request.get_json()
        if data['permissions']:
            user.permissions = data['permissions']
            db.session.commit()
            return jsonify({'success': 'true'})
    else:
        return jsonify({'success': 'false', 'errorMessage': 'user not found'}), 400
