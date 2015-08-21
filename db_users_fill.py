#!/usr/bin/env python

# This is a test fill in script. It is intended to run once, but if you will run it again it will fail to add records to databese because of unique field requeremnt

from app import db, models
import datetime

u = models.User(username='admin', email='admin@email.org', password='admin', role=models.ROLE_ADMIN)
db.session.add(u)
db.session.commit()

u = models.User(username='reader', email='reader@email.org', password='reader', role=models.ROLE_USER, first_name='Read', last_name='Books')
db.session.add(u)
db.session.commit()

