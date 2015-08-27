#!/usr/bin/env python
# -*- coding: utf8 -*-

# This is a test fill in script. It is intended to run once, but if you will run it again it will fail to add records to databese because of unique field requeremnt

from app import db, models

message=u'Воруют, воруют, воруют'
m = models.Message(title=u'Сообщение о воровстве', message=message, contacts=u'1234567')
db.session.add(m)
db.session.commit()

message=u'Везде бардак, директор бардак, бухгалтер бардак, всё бардак'
m = models.Message(title=u'Сообщение о бардаке', message=message, contacts=u'bardak@yandex.ru')
db.session.add(m)
db.session.commit()

message=u'Они делали это, фотки в файле'
m = models.Message(title=u'Непристойное поведение', message=message, contacts=u'stukach@mail.ru', filename='file.zip')
db.session.add(m)
db.session.commit()

message=u'субж'
m = models.Message(title=u'Вы все казлы', message=message, contacts=u'не скажу')
db.session.add(m)
db.session.commit()

message=u'ticket test'
m = models.Message(title=u'ticket test', message=message, contacts=u'ticket@ticket.com')
db.session.add(m)
db.session.commit()

message=u'ticket test'
m = models.Message(title=u'ticket test', message=message, contacts=u'ticket@ticket.com')
db.session.add(m)
db.session.commit()

message=u'ticket test'
m = models.Message(title=u'ticket test', message=message, contacts=u'ticket@ticket.com')
db.session.add(m)
db.session.commit()


