from flask_login import UserMixin

from app import db, login
from enum import IntEnum
from werkzeug.security import *


class UserPermissions(IntEnum):
    REGULAR_USER = 0
    ADMIN = 1


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    permissions = db.Column(db.Integer)

    def __init__(self, password, **kwargs):
        super(User, self).__init__(**kwargs)
        self.password_hash = generate_password_hash(password=password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login.user_loader
def load_user(id_):
    return User.query.get(int(id_))
