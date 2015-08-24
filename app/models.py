# -*- coding: utf8 -*-

from app import db, bcrypt, app
from flask import flash, abort, g
import time
import datetime as dt
import sys, os
import zlib, hashlib 
import config


ROLE_ADMIN = 2
ROLE_USER = 1
roles = { ROLE_ADMIN : u'Администратор',
          ROLE_USER  : u'Пользователь'
        }


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    ts = db.Column(db.DateTime, nullable=False)
    username = db.Column(db.String(config.MODEL_USERNAME), index = True, unique=True, nullable=False)
    email = db.Column(db.String(config.MODEL_EMAIL), nullable=False)
    first_name = db.Column(db.Unicode(config.MODEL_FIRSTNAME), nullable=True)
    last_name = db.Column(db.Unicode(config.MODEL_LASTNAME), nullable=True)
    password = db.Column(db.String(config.MODEL_PASSHASH), nullable=True)
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
        try:
          role = roles[self.role]
        except KeyError:
          role = u'неизвестно'
        return role

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password)

    def check_password(self, value):
        return bcrypt.check_password_hash(self.password, value)

    @staticmethod
    def password_is_strong(password) :

        lower = False
        upper = False
        number = False
        other = False
        for c in password :
          if c.isalpha() :
            if c.islower() : lower = True
            if c.isupper() : upper = True
          elif c.isdigit() : number = True
          else : other = True
        if app.debug :
          print 'Checking password strength:'
          print 'lower {0}, upper {1}, number {2}, other {3}'.format(lower, upper, number, other)
        if (lower+upper+number+other) > 2 : return True
        return False

    @property
    def full_name(self):
        return u"{0} {1}".format(self.first_name, self.last_name)

    @staticmethod
    def roles_choices() :
        choices = [] 
        for k in roles.keys() :
          choice = (str(k), roles[k])
          choices.append(choice)
        print choices
        return choices

    def __repr__(self):
        r =    u'<User ' + self.username + u' (' + self.first_name + u' ' + self.last_name + u'), email ' + self.email + u', role ' + unicode(self.role) + u'(' + self.get_role() + u') created on ' + unicode (self.ts) + u'>'
        return r.encode('utf-8')
#.format(self.username, self.first_name.decode('utf-8'), self.last_name.decode('utf-8'), self.email, self.role, self.get_role().decode('utf-8'), self.ts)


class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key = True)
    ts = db.Column(db.DateTime, nullable=False)
    ticket = db.Column(db.String(config.MODEL_TICKET))
    title = db.Column(db.Unicode(config.MODEL_TITLE))
    message = db.Column(db.Unicode(config.MODEL_MESSAGE))
    contacts = db.Column(db.Unicode(config.MODEL_CONTACTS))
    filename = db.Column(db.String(config.MODEL_FILENAME)) # 'none', if no file
    
    def __init__(self, title, message, contacts, filename=None, **kwargs):
        db.Model.__init__(self, **kwargs)
        self.ts = dt.datetime.utcnow()
        self.ticket=hex(zlib.adler32(unicode(self.ts).encode('utf-8') + message.encode('utf-8'))).strip('-')
        self.title = title
        self.message = message
        self.contacts = contacts
        if filename :
          if app.debug :
            print 'Message recieved filename ' + filename
          '''
          filename is stored in tmp folder
          maybe after antivirus scan
          need to move it to DB or another location
          for now we will store it under files folder
          with the name equal to file hash (sha-something)
          '''
          zfilename = os.path.join(config.DOWNLOAD_DIR, filename)
          if os.path.isfile(zfilename) :
            
            newfilename = (hashlib.sha256(file(zfilename, 'rb').read()).hexdigest())
            znewfilename = os.path.join(FILES_DIR, newfilename + '.zip')
            if app.debug :
              print 'sha hash: ' + newfilename
              print 'hash len: ' + str(len(newfilename))
              print 'new file: ' + znewfilename

            os.rename(zfilename, znewfilename)
            self.filename = newfilename
        else :
          self.filename = None
        '''
        if email : self.email = email
        '''

