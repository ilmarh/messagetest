#!/usr/bin/env python

# This is a test script to empty user database.

from app import db, models

users = models.User.query.all()
for u in users:
	db.session.delete(u)
db.session.commit()

