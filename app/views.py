# -*- coding: utf8 -*-

import os, zlib
from flask import render_template, flash, redirect, session, url_for, request, g, jsonify, abort, send_file
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required, fresh_login_required
from .models import User, Message, ROLE_ADMIN, ROLE_USER #, Post
from .forms import LoginForm, MessageForm, ReaderForm, UsersForm, NewUserForm, EditUserForm, ProfileForm
from .emails import send_email
from app import app, lm, db, mail
from config import MSG_PER_PAGE, DOWNLOAD_DIR, FILES_DIR
from werkzeug import secure_filename



@app.before_request
def before_request():
    g.user = current_user


@app.route('/')
@app.route('/index')
def index():

  g.user = current_user
  if g.user is not None and g.user.is_authenticated():
    return redirect(url_for('logout'))

  return render_template("index.html", title = u'Внимание!')


@app.route('/login', methods = ['GET', 'POST'])
def login():

    form = LoginForm()

    if form.validate_on_submit():
      u = form.user
      if app.debug : print u'{0}'.format(u).encode('utf-8')
      app.logger.info(u'Login: {0}\n'.format(u))

      login_user(u)

      # XXX: maybe insert redirection URL from models
      if u.is_admin(): return redirect('/admin')
      else : return redirect('/messages')
    elif request.method == 'POST' :
      if app.debug :
        print u'user {0} pass {1}'.format(form.username.data, form.password.data).encode('utf-8')
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
        filename = None
        if form.archive.data :
          filename = secure_filename(form.archive.data.filename)
          if app.debug :
            print form.archive.data
            print type(form.archive.data)
            print filename
          #filename = os.path.join(DOWNLOAD_DIR, secure_filename(form.archive.data.filename))
          #zfilename = DOWNLOAD_DIR + '/' + filename
          zfilename = os.path.join(DOWNLOAD_DIR, filename)
          if app.debug :
            print zfilename
          if os.path.isfile(zfilename) :
            os.remove(zfilename)
          form.archive.data.save(zfilename)

        m = Message(title=form.title.data, message=form.message.data, contacts=form.contacts, filename=filename)
        db.session.add(m)
        db.session.commit()

        # Send email to reader user
        recipients = []
        q = User.query.all()
        for u in q :
          if not u.is_admin() and u.email :
            recipients.append(u.email)
        if app.debug : print 'Recipients : ' + str(recipients)
        send_email(subject=u'Новое сообщение горячей линии', recipients=recipients, 
                   body=u'В ' + unicode(m.ts.strftime("%Y-%m-%d %H-%M-%S UTC")) + u' Получено новое сообщение на тему: ' + m.title)

        app.logger.info(u'Message commited: ticket {0}\n'.format(m.ticket))
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

      logstr = u"Download: file {0} by {1}\n".format(name, g.user)
      app.logger.info(logstr)
      zfilename = os.path.join(FILES_DIR, name + '.zip')
      #zfilename = '/files/123456.zip'
      if app.debug : print 'Downloading file {0}'.format(zfilename)
      if os.path.isfile(zfilename) :
        return send_file(zfilename, as_attachment = True, attachment_filename = 'attach.zip')
      else :
        return redirect('/index')
      
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
      form.users = User.query.all()

      if form.validate_on_submit() :
        user_ids = request.form.getlist("users_action")
        recs = []
	for u in form.users : recs.append(u.username)
        for user_id in user_ids :
	  if not user_id in recs :
            if app.debug :
	      print user_ids
	      print recs
	      flash(u"В запросе POST указаны неверные данные о пользователях")
	    app.logger.error(u"Error: wrong users {0} in POST request".format(recs))
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
            app.logger.info(u'User delete: {0} deleted {1}\n'.format(g.user, user))
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
            flash(u'Выберите хотя бы одного пользователя для редактирования!')
            return redirect('/admin/users')
          return redirect('/admin/users/edit/{0}'.format(user_ids[0]))

      return render_template("admin/users.html", title = u'Управление пользователями', form=form)
                                
    app.logger.info(u'Error: user {0} is not admin, tried to access admin page /admin\n'.format(g.user))
    flash('Not admin role' , 'error')
    return redirect('/')


@app.route('/admin/users/add', methods = ['GET', 'POST'])
@fresh_login_required
def add_user():
    if g.user.is_admin():
        form = NewUserForm()


        if form.validate_on_submit() :
                if form.cancel_button.data :
                  if app.debug : print "cancel user add"
                  return redirect('/admin/users')
                if form.apply_button.data :
                        '''
                        Need to check input strings userid, email, first, last names!
                        '''
			if User.query.filter_by(username=form.userid.data).first():
                                app.logger.info(u'Error: {0} tried to add existing username {1}\n'.format(g.user, form.userid.data))
				flash('Username exists!')
				return redirect('/admin/users/add')
                        if app.debug : print "add user"

			user = User(username=form.userid.data,
                                    password=form.password.data,
                                    email=form.email.data,
                                    role=form.get_role(),
                                    first_name=form.first.data,
                                    last_name=form.last.data)
			#logstr = unicode(g.user) + u" added user " + unicode(user) + u"\n"
			logstr = u'User add: {0} added user {1}\n'.format(g.user,user)
			app.logger.info(logstr)
			db.session.add(user)
			db.session.commit()
                return redirect('/admin/users')
	elif request.method != "POST":
                pass
                #print request.method
		#app.logger.info('Add user: wrong method ({0}) used\n'.format(request.method))
		#form.role.data = form.get_default_role()
        else : # request.method == 'POST' :
          if form.cancel_button.data :
            if app.debug : print "cancel user add"
            return redirect('/admin/users')
          if app.debug :
            print "message form not validated"
            print form.errors
            for field in form.errors :
              err = form.errors[field]
              for errmsg in err :
                flash(errmsg, 'error')


        return render_template("admin/useradd.html", title = u'Новый пользователь', form=form)

    app.logger.info(u'Error: user {0} is not admin, tried to access admin page /admin/users/add\n'.format(g.user))
    flash('Not admin role' , 'error')
    return redirect('/')


'''
Административная ссылка, чтобы редактировать пользователей админом!
'''
@app.route('/admin/users/edit/<userid>', methods = ['GET', 'POST'])
@fresh_login_required
def edit_user(userid):

    if g.user.is_admin():
      u = User.query.filter_by(username=userid).first()
      if not u :
        if app.debug : print "Edit user: userid not found"
        return redirect('/admin/users')

      form = EditUserForm()

      if form.validate_on_submit() :
        if form.cancel_button.data :
          if app.debug : print "cancel user edit"
          return redirect('/admin/users')
        if form.apply_button.data :
          if form.password.data:
            u.set_password(form.password.data)
          if form.email.data :
            u.email = form.email.data
	  if form.role.data : u.role = form.get_role()

          logstr = u'Profile change: {0} changed profile of {1}\n'.format(g.user, u)
          app.logger.info(logstr)
	  db.session.add(u)
	  db.session.commit()

          return redirect('/admin/users')

      elif request.method != "POST":
        form.email.data = u.email
        form.set_role(u.role)
      else : # request.method == 'POST' :
        if form.cancel_button.data :
          if app.debug : print "cancel user edit"
          return redirect('/admin/users')
        if app.debug :
          print "message form not validated"
          print form.errors
          for field in form.errors :
            err = form.errors[field]
            for errmsg in err :
              flash(errmsg, 'error')

      return render_template("admin/useredit.html", title = u'Изменение пользователя', form=form)

    app.logger.info(u'Error: user {0} is not admin, tried to access admin page /admin/users/edit\n'.format(g.user))
    flash('Not admin role' , 'error')
    return redirect('/')


@app.route('/profile', methods = ['GET', 'POST'])
@fresh_login_required
def edit_profile():

    if g.user.is_authenticated() and not g.user.is_admin():
      print "edit profile"

      form = ProfileForm(g.user)

      if form.validate_on_submit() :

        if form.cancel_button.data :
          if app.debug : print "cancel profile change"
          return redirect('/messages')

        if form.apply_button.data :
          u = g.user
          if form.password1.data : u.set_password(form.password1.data)
          if form.email.data : u.email = form.email.data

          logstr = u'Profile change: {0} changed own profile\n'.format(g.user)
          app.logger.info(logstr)

          db.session.add(form.user)
          db.session.commit()
          print "changed profile"
          return redirect('/messages')

      elif request.method != "POST":
        form.email.data = g.user.email
      else : # request.method == 'POST' :
        if form.cancel_button.data :
          if app.debug : print "cancel user edit"
          return redirect('/messages')
        if app.debug :
          print "message form not validated"
          print form.errors
          for field in form.errors :
            err = form.errors[field]
            for errmsg in err :
              flash(errmsg, 'error')


      return render_template("profile.html", title = u'Изменение профиля', form=form)

    elif g.user.is_authenticated() and g.user.is_admin():
      flash(u'Администратор изменяет свой профиль через форму изменения данных пользователя в БД' , 'error')
      return redirect('/admin/users')

    flash('Not authenticated' , 'error')
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
