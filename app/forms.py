# -*- coding: utf8 -*-

from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField
from flask.ext.wtf.file import FileField, FileAllowed, FileRequired
from wtforms.validators import DataRequired, Optional, Email, Length, EqualTo

from .models import User
import config


class LoginForm(Form):
    username = StringField('username', 
                           validators = [DataRequired(u'Не введено имя пользователя'),
                                         Length(max=config.MODEL_USERNAME,
                                                message=u'Имя пользователя должно быть не более {0} символов'.format(config.MODEL_USERNAME))])
    password = PasswordField('password',
                             validators = [DataRequired(u'Не введён пароль'),
                                           Length(max=config.MODEL_PASSWORD, min=8,
                                                  message=u'Пароль должен быть длиной от 8 до {0} символов'.format(config.MODEL_PASSWORD))])

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self):
        initial_validation = super(LoginForm, self).validate()
        if not initial_validation:
            print "LoginForm: initial_validation failed"
            return False

        self.user = User.query.filter_by(username=self.username.data).first()
        if not self.user:
            print "LoginForm: invalid username or password 1"
            self.username.errors.append(u'Неверное имя пользователя или пароль')
            return False

        if not self.user.check_password(self.password.data):
            print "LoginForm: invalid username or password 2"
            self.password.errors.append(u'Неверное имя пользователя или пароль')
            return False

        print "LoginForm: validation Ok"
        return True


class MessageForm(Form):
    title = StringField('title',
                        validators = [DataRequired(u'Необходимо заполнить заголовок'),
                                      Length(max=config.MODEL_TITLE,min=10,
                                             message=u'Заголовок должен быть от 10 до {0} символов'.format(config.MODEL_TITLE))])
    message = TextAreaField('message',
                            validators = [DataRequired(u'Необходимо заполнить тело сообщения'),
                                          Length(max=config.MODEL_MESSAGE,min=10,
                                          message=u'Тело сообщения должно быть от 10 до {0} символов'.format(config.MODEL_MESSAGE))])
    email = StringField('email',
                        validators = [Email(u'Неправильно введён Email'),
                                      Optional(),
                                      Length(max=config.MODEL_EMAIL,
                                             message=u'Email должен быть не более {0} символов'.format(config.MODEL_EMAIL))]) #inputtext (email, telephone, etc)
    telephone = StringField('telephone',
                            validators = [Optional(),
                                          Length(max=config.MODEL_TELEPHONE,
                                                 message=u'Телефонный номер должен быть не более {0} символов'.format(config.MODEL_TELEPHONE))]) #inputtext (email, telephone, etc)
    archive = FileField('archive', validators=[Optional(), FileAllowed(['zip'], u'Файл должен быть zip-архивом!')])
    send_button = SubmitField(u'Отправить')

    def __init__(self, *args, **kwargs):
        super(MessageForm, self).__init__(*args, **kwargs)
        self.contacts = u''

    def validate(self):
        initial_validation = super(MessageForm, self).validate()
        if not initial_validation:
            print "MessageForm: initial_validation failed"
            return False

        if self.send_button.data: 
          if not self.email.data and not self.telephone.data :
            self.email.errors.append(u'Должны быть указаны контактные данные (хотя бы email)')
            self.telephone.errors.append(u'Должны быть указаны контактные данные (хотя бы телефон)')
            print u'Email ' + self.email.data.encode('utf-8') + u' and Telefone ' + self.telephone.data.encode('utf-8') + u' not set'
            return False
          elif self.email.data and self.telephone.data :
            try :
              tel = int(self.telephone.data)
            except ValueError: 
              print u'Telephone error ' + self.telephone.data.encode('utf-8')
              self.telephone.errors.append(u'Телефонный номер должен состоять из цифр')
              return False
            if tel < 0 :
              self.telephone.errors.append(u'Телефонный номер должен состоять из цифр')
              return False
            self.contacts = self.email.data + u', ' +  self.telephone.data
            print self.contacts.encode('utf-8')
          elif self.email.data and not self.telephone.data :
            self.contacts = self.email.data
            print self.contacts.encode('utf-8')
          else :
            try :
              tel = int(self.telephone.data)
            except ValueError: 
              print u'Telephone error ' + self.telephone.data.encode('utf-8')
              self.telephone.errors.append(u'Телефонный номер должен состоять из цифр')
              return False
            if tel < 0 :
              self.telephone.errors.append(u'Телефонный номер должен состоять из цифр')
              return False
            self.contacts = self.telephone.data
        return True # Any data is ok

class ReaderForm(Form):
    searchstr = StringField(u'Поиск', validators = [DataRequired()])
    #ok = Button()
    #cancel = Button()


class UsersForm(Form):

        add_button = SubmitField(u'Добавить')
        delete_button = SubmitField(u'Удалить')
        edit_button = SubmitField(u'Изменить')

class UserForm(Form):

        passwordold = PasswordField('password',
                                    validators=[DataRequired(),
                                                Length(max=config.MODEL_PASSWORD, min=8,
                                                       message=u'Пароль должен быть длиной от 8 до {0} символов'.format(config.MODEL_PASSWORD))])
        password1 = PasswordField('newpassword',
                                  validators=[Optional(),
                                              Length(max=config.MODEL_PASSWORD, min=8,
                                                     message=u'Пароль должен быть длиной от 8 до {0} символов'.format(config.MODEL_PASSWORD)),
                                              EqualTo('password2')])
        password2 = PasswordField('confirmpassword', validators=[Optional()])
        email = StringField('email',
                            validators = [Email(u'Неправильно введён Email'),
                                          Optional(),
                                          Length(max=config.MODEL_EMAIL,
                                                 message=u'Email должен быть не более {0} символов'.format(config.MODEL_EMAIL))])
        apply_button = SubmitField(u'Сохранить')
        cancel_button = SubmitField(u'Отменить')

class EditUserForm(Form) :

        password = PasswordField('password',
                                 validators=[DataRequired(),
                                             Length(max=config.MODEL_PASSWORD, min=8,
                                                    message=u'Пароль должен быть длиной от 8 до {0} символов'.format(config.MODEL_PASSWORD))])
        email = StringField('email',
                            validators = [Email(u'Неправильно введён Email'),
                                          Optional(),
                                          Length(max=config.MODEL_EMAIL,
                                                 message=u'Email должен быть не более {0} символов'.format(config.MODEL_EMAIL))])
        role = SelectField('role', validators = [DataRequired()])
        apply_button = SubmitField(u'Сохранить')
        cancel_button = SubmitField(u'Отменить')

class NewUserForm(EditUserForm):

        userid = StringField('userid', 
                             validators = [DataRequired(u'Не введено имя пользователя'),
                                         Length(max=config.MODEL_USERNAME,
                                                message=u'Имя пользователя должно быть не более {0} символов'.format(config.MODEL_USERNAME))])
        first = StringField('first', validators=[DataRequired()])
        last = StringField('last', validators=[DataRequired()])


