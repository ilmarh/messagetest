#!/usr/bin/env python
# -*- coding: utf8 -*-

# This is a test fill in script. It is intended to run once, but if you will run it again it will fail to add records to databese because of unique field requeremnt

from app import db, models
import datetime

u = models.User(username='admin', email='admin@email.org', password='Adminpass!', role=models.ROLE_ADMIN, first_name=u'Петр', last_name=u'Петров')
db.session.add(u)
db.session.commit()

u = models.User(username='reader', email='reader@email.org', password='Readerpass!', role=models.ROLE_USER, first_name=u'Иван', last_name=u'Иванов')
db.session.add(u)
db.session.commit()

