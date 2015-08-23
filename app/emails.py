from flask import render_template
from flask.ext.mail import Message
from app import app, mail
from config import MAIL_SENDER
from threading import Thread


def async(f):
    def wrapper(*args, **kwargs):
        thr = Thread(target=f, args=args, kwargs=kwargs)
        thr.start()
    return wrapper

@async
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, recipients, body, sender=MAIL_SENDER) :
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = body
    # send_async_email(app, msg)
    print 'Email: '
    print msg

'''
def follower_notification(followed, follower):
    send_email("[microblog] %s is now following you!" % follower.nickname,
               ADMINS[0],
               [followed.email],
               render_template("follower_email.txt",
                               user=followed, follower=follower),
               render_template("follower_email.html",
                               user=followed, follower=follower))
'''
