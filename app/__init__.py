from flask import Flask
import os

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'secret_key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', "sqlite:////tmp/test.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

# Login
login = LoginManager(app)
login.login_view = 'login'

from app import routes, models

db.create_all(app=app)

# seed
if not models.User.query.count():
    u = models.User(username="admin",
                    password="pass",
                    permissions=models.UserPermissions.ADMIN)
    db.session.add(u)
    db.session.commit()
