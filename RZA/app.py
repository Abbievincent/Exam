import requests
import json

import os
import os.path as op

from datetime import datetime as dt
from sqlalchemy import Column, Integer, DateTime
from flask import Flask, render_template, url_for, redirect, request
from flask import session as login_session
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.event import listens_for
from markupsafe import Markup
from flask_admin import Admin, form
from flask_admin.form import rules
from flask_admin.contrib import sqla, rediscli
from PIL import Image
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import relationship
from sqlalchemy import select


UPLOAD_FOLDER = 'static'
app = Flask(__name__, static_folder='static')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['FLASK_ADMIN_SWATCH'] = 'cosmo'
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\722973\\DB Browser for SQLite\\site.db'
app.config['SECRET_KEY'] = 'this is a secret key '
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    # hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    # password=hashed_password

def __repr__(self):
    return f'<User {self.username}>'


class Customer(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False)


def __str__(self):
    return self.username

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/home')
def option():
    return render_template('home.html')


if __name__ == "__app__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)