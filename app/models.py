# -*- coding: utf8 -*-

from app import db, bcrypt
from flask import flash, abort, g
import time
import datetime as dt
import sys
from hashlib import md5
import zlib
import re


ROLE_ADMIN = 2
ROLE_USER = 1


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    ts = db.Column(db.DateTime, nullable=False)
    username = db.Column(db.String(80), index = True, unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(30), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    password = db.Column(db.String(128), nullable=True)
    role = db.Column(db.SmallInteger, default = ROLE_USER)

    def __init__(self, username, email, password=None, **kwargs):
        db.Model.__init__(self, username=username, **kwargs)
        self.ts = dt.datetime.utcnow()
        if email : self.email = email
        if password:
            self.set_password(password)
        else:
            self.password = None

    def is_authenticated(self):
        return True
 
    def is_active(self):
        return True
 
    def is_anonymous(self):
        return False
 
    def is_admin(self):
	return (self.role == ROLE_ADMIN)

    def get_id(self):
        return unicode(self.id)

    def get_role(self):
        role = 'unknown'
        if self.role == ROLE_ADMIN : role = 'admin'
        if self.role == ROLE_USER : role = 'user'
        return role

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password)

    def check_password(self, value):
        return bcrypt.check_password_hash(self.password, value)

    @property
    def full_name(self):
        return "{0} {1}".format(self.first_name, self.last_name)

    def __repr__(self):
        return '<User {0} ({1} {2}), email {3}, role {4} ({5}) created on {6}>'.format(self.username, self.first_name, self.last_name, self.email, self.role, self.get_role(), self.ts)


class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key = True)
    ts = db.Column(db.DateTime, nullable=False)
    ticket = db.Column(db.String(10))
    title = db.Column(db.String(140))
    message = db.Column(db.String(4500))
    contacts = db.Column(db.String(150))
    filename = db.Column(db.String(128)) # 'none', if no file
    
    def __init__(self, title, message, contacts, filename=None, **kwargs):
        db.Model.__init__(self, **kwargs)
        self.ts = dt.datetime.utcnow()
        self.ticket=hex(zlib.adler32(unicode(self.ts).encode('utf-8') + message.encode('utf-8'))).strip('-')
        self.title = title
        self.message = message
        self.contacts = contacts
        self.filename = filename
        '''
        if email : self.email = email
        if password:
            self.set_password(password)
        else:
            self.password = None
        '''

