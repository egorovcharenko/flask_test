from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Log in')


class AddUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    permissions = BooleanField('Is Admin', default=False)
    submit = SubmitField('Add user')
