# -*- coding: utf8 -*-

import os, zlib
from flask import render_template, flash, redirect, session, url_for, request, g, jsonify, abort, send_file
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required, fresh_login_required
from .models import User, Message, ROLE_ADMIN, ROLE_USER #, Post
from .forms import LoginForm, MessageForm, ReaderForm, UsersForm, NewUserForm
from app import app, lm, db
from config import MSG_PER_PAGE

main_links = [{'url':'/login', 'label':u'Вход'},{'url':'/message', 'label':u'Сообщение'}]


@app.before_request
def before_request():
    g.user = current_user


@app.route('/')
@app.route('/index')
def index():

  g.user = current_user
  if g.user is not None and g.user.is_authenticated():
    return redirect(url_for('logout'))

  links = main_links
  return render_template("index.html", title = u'Внимание!', links=links)


@app.route('/login', methods = ['GET', 'POST'])
def login():

    form = LoginForm()

    if form.validate_on_submit():
      u = form.user
      if app.debug : print u
      app.logger.info('User login: {0}\n'.format(u))

      login_user(u)

      if u.is_admin(): return redirect('/admin')
      else : return redirect('/messages')
    elif request.method == 'POST' :
      if app.debug :
        print u'user ' + form.username.data.encode('utf-8') + u' pass ' + form.password.data.encode('utf-8')
        print "login form not validated"
        print form.errors
      for field in form.errors :
        err = form.errors[field]
        for errmsg in err :
          flash(errmsg, 'error')

    return render_template('login.html', title = u'Вход', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/message', methods = ['GET', 'POST'])
def post_message():

    if g.user.is_anonymous() :

      form = MessageForm()

      if form.validate_on_submit():
        if app.debug : print "message form validated"
        if app.debug : print "message submited"
        # Need to add here some hook to show Ticket number
        m = Message(title=form.title.data, message=form.message.data, contacts=form.contacts, filename=None)
        db.session.add(m)
        db.session.commit()
        app.logger.info('Message with ticket {0} commited\n'.format(m.ticket))
        return render_template('ticket.html', title = u'Номер', ticket=m.ticket)

      elif request.method == 'POST' :
        if app.debug :
          print "message form not validated"
          print form.errors
        for field in form.errors :
          err = form.errors[field]
          for errmsg in err :
            flash(errmsg, 'error')

      return render_template('postmessage.html', title = u'Сообщение', form=form)

    else :
      return redirect('/index')

'''
URI для отображения таблицы с записанными сообщениями
Должно быть реализовано разбиение больших таблиц на страницы с навигацией
'''
@app.route('/messages', methods = ['GET', 'POST'])
@app.route('/messages/<page>', methods = ['GET', 'POST'])
@fresh_login_required
def show_messages(page=1):

  if not g.user.is_admin() :

    if app.debug :
      print "Show messages"
      print page
      print type(page)
    page = int(page)
    q = Message.query.paginate(page, MSG_PER_PAGE, False) # have hardcoded value 5!!! Change it
    #q = Message.query.all()
    if app.debug :
      print type(page)
      print "messages len = {0}".format(len(q.items))
      print q.items

    return render_template("showmessages.html", title=u'Сообщения', page=page, messages=q)
  
  return redirect('/')

'''
URI для отображения записанного сообщения
Наверное можно прикрутить кнопки для удаления сообщения и пометить, как отработанное
'''
@app.route('/message/<msgid>', methods = ['GET', 'POST'])
@fresh_login_required
def show_message(msgid):

    if not g.user.is_anonymous() and not g.user.is_admin():

      '''
      Пока просто отображение
      form = MessageForm()

      if form.validate_on_submit():
        if app.debug : print "message form validated"
        if form.ok_button.data:
          if app.debug : print "message submited"
          # Need to add here some hook to show Ticket number
          data = form.message.data
          m = Message(title=form.title.data, message=form.message.data, contacts=form.contacts, filename=None)
          db.session.add(m)
          db.session.commit()
          app.logger.info('Message with ticket {0} commited\n'.format(m.ticket))
          return render_template('ticket.html', title = u'Номер', ticket=m.ticket)

        elif form.cancel_button.data:
          if app.debug : print "message canceled"
          return redirect('/index')
      elif request.method == 'POST' :
        if app.debug :
          print "message form not validated"
          print form.errors
        for field in form.errors :
          err = form.errors[field]
          for errmsg in err :
            flash(errmsg, 'error')
      '''

      m = Message.query.filter_by(id=msgid).first() 
      if m :
        page = (int(msgid) - 1)/MSG_PER_PAGE + 1

        return render_template('showmessage.html', title = u'Сообщение', msg=m, page=page)
      else :
        return redirect('/index')

    else :
      return redirect('/index')


'''
URI для скачивания файлов из сообщений
Файлы храняться отдельно, в базе есть только имена
Существует проблема нарушения целостности этих данных
Но это больше прототип, который можно в последствии доработать
В том числе перейти на мускул/постгресс с хранением файлов прямо в базе, тогда отдаваться будет файл прямо оттуда
'''
@app.route('/file/<name>', methods = ['GET', 'POST'])
@fresh_login_required
def download_file(name):

    if not g.user.is_anonymous() and not g.user.is_admin():

      logstr = "User " + str(g.user) + " downloaded file " + name
      app.logger.info(logstr)
      zfilename = os.path.join(app.config['DOWNLOAD_DIR'], '123456' + '.zip')
      #zfilename = '/files/123456.zip'
      if app.debug : print 'Downloading file {0}'.format(zfilename)
      return send_file(zfilename, as_attachment = True, attachment_filename = 'attach.zip')
      
      '''
    Здесь отдаётся доп-файл
    1. Проверить, что такой существует
    2. Отдать
      '''
    else :
      return redirect('/index')



@app.route('/admin/', methods = ['GET', 'POST'])
@app.route('/admin/users', methods = ['GET', 'POST'])
@fresh_login_required

def users():
    if g.user.is_admin():
      form = UsersForm()
      users = []

      q = User.query.all()
      for u in q :
        user = {"username":u.username,"first":u.first_name,"last":u.last_name,"email":u.email,"role":u.get_role()}
        users.append(user)
      form.users = users

      if form.validate_on_submit() :
        user_ids = request.form.getlist("users_action")
        recs = []
	for rec in form.users :
			recs.append(rec['username'])
        for user_id in user_ids :
			if not user_id in recs :
                          if app.debug :
			    print user_ids
			    print recs
			    flash(u"В запросе POST указаны неверные данные о пользователях")
			  app.logger.error("Wrong users in POST request")
			  return redirect('/admin/users')
        if form.add_button.data :
                  if app.debug :
		    print "do add"
		    print user_ids
		  return redirect('/admin/users/add')
        if form.delete_button.data :
          if app.debug :
            print "do delete"
            print user_ids
          for user_id in user_ids :
            user = User.query.filter_by(username=user_id).first()
            if app.debug : print user
            app.logger.info('User {0} issued delete command for user {1}\n'.format(g.user, user))
            db.session.delete(user)
            db.session.commit()
          return redirect('/admin/users')

        if form.edit_button.data :
          if app.debug :
            print "do edit"
            print user_ids
          if len(user_ids) > 1 :
            flash(u'Выберите только одного пользователя для редактирования!')
            return redirect('/admin/users')
          if len(user_ids) == 0 :
            flash(u'Выберите только одного пользователя для редактирования!')
            return redirect('/admin/users/edit/{0}'.format(user_ids[0]))

      return render_template("admin/users.html", title = u'Управление пользователями', form=form)
                                
    app.logger.info('User {0} is not admin, tried to access admin page /admin\n'.format(g.user))
    flash('Not admin role' , 'error')
    return redirect('/')


@app.route('/admin/users/add', methods = ['GET', 'POST'])
@fresh_login_required
def add_user():
    if g.user.is_admin():
        form = NewUserForm()

        form.role.choices = [('admin', u'Администратор'),('user', u'Пользователь')]

        if form.validate_on_submit() :
                if form.apply_button.data :
                        '''
                        Need to check input strings userid, email, first, last names!
                        '''
			if User.query.filter_by(username=form.userid.data).first():
                                app.logger.info('User {0} tried to add existing username {1}\n'.format(g.user, form.userid.data))
				flash('Username exists!')
				return redirect('/admin/users/add')
                        if app.debug : print "add user"
			if form.role.data == 'admin':
			  role = ROLE_ADMIN
			elif form.role.data == 'user':
			  role = ROLE_USER
			else :
                                app.logger.info('User {0} tried to add user {1} with wrong role {2}\n'.format(g.user, form.userid.data, form.role.data))
				flash('wrong role!')
				return redirect('/admin/users/add')
                        '''
			if form.email.data : user.email = form.email.data
			if form.first_name.data : user.first_name = form.first_name.data
			if form.last_name.data : user.last_name = form.last_name.data
                        '''
			user = User(username=form.userid.data, password=form.password.data, email=form.email.data, role=role)
			db.session.add(user)
			db.session.commit()
			logstr = str(g.user) + " added user " + str(user) + "\n"
			app.logger.info(logstr)
                if form.cancel_button.data :
                        if app.debug : print "cancel user add"
                return redirect('/admin/users')
	elif request.method != "POST":
		app.logger.info('Add user: wrong method ({0}) used\n'.format(request.method))
		form.role.data = ROLE_USER
	else :
		if app.debug:
                  print 'Form data: userid {0}, role {1}'.format(form.userid.data, role=form.role.data)
                  print form.errors
		app.logger.debug(form.errors)
		flash('form was not validated', 'error')
                return redirect('/admin/users')

        return render_template("admin/useradd.html", title = u'Новый пользователь', form=form)

    app.logger.info('User {0} is not admin, tried to access admin page /admin/users/add\n'.format(g.user))
    flash('Not admin role' , 'error')
    return redirect('/')



#
###### ERROR HANDLERS ##############
#


@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(405)
def not_found_error(error):
    return render_template('errors/405.html'), 405
