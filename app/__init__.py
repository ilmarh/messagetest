import os
from flask import Flask, g
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from flask.ext.bcrypt import Bcrypt
from flask.ext.mail import Mail
from config import basedir, LOGFILE, RECAPTCHA_TESTING

app = Flask(__name__)

app.config.from_object('config')

lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'
lm.session_protection = "strong"
#oid = OpenID(app, os.path.join(basedir, 'tmp'))

db = SQLAlchemy(app)

bcrypt = Bcrypt(app)

mail = Mail(app)

app.testing = RECAPTCHA_TESTING

from app import models, views

@lm.user_loader
def load_user(id):
    return models.User.query.get(int(id))

if not app.debug:
    import logging
    from logging.handlers import RotatingFileHandler
    file_handler = RotatingFileHandler(LOGFILE, 'a', 1 * 1024 * 1024, 10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('messages startup')


