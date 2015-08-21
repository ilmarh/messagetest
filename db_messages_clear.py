#!/usr/bin/env python

# This is a test script to empty user database.

from app import db, models

messages = models.Message.query.all()
for m in messages:
	db.session.delete(m)
db.session.commit()

