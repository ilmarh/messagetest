# -*- coding: utf8 -*-

from flask.ext.wtf import Form#, RecaptureField
from flask_wtf.recaptcha import RecaptchaField
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField
from flask.ext.wtf.file import FileField, FileAllowed, FileRequired
from wtforms.validators import DataRequired, Optional, Email, Length, EqualTo

from .models import User
import config


class LoginForm(Form):
    username = StringField(u'Идентификатор:', 
                           validators = [DataRequired(u'Не введено имя пользователя'),
                                         Length(max=config.MODEL_USERNAME,
                                                message=u'Имя пользователя должно быть не более {0} символов'.format(config.MODEL_USERNAME))])
    password = PasswordField(u'Пароль:',
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
    title = StringField(u'Заголовок:',
                        validators = [DataRequired(u'Необходимо заполнить заголовок'),
                                      Length(max=config.MODEL_TITLE,min=10,
                                             message=u'Заголовок должен быть от 10 до {0} символов'.format(config.MODEL_TITLE))])
    message = TextAreaField(u'Сообщение:',
                            validators = [DataRequired(u'Необходимо заполнить тело сообщения'),
                                          Length(max=config.MODEL_MESSAGE,min=10,
                                          message=u'Тело сообщения должно быть от 10 до {0} символов'.format(config.MODEL_MESSAGE))])
    email = StringField(u'Почта:',
                        validators = [Email(u'Неправильно введён Email'),
                                      Optional(),
                                      Length(max=config.MODEL_EMAIL,
                                             message=u'Email должен быть не более {0} символов'.format(config.MODEL_EMAIL))]) #inputtext (email, telephone, etc)
    telephone = StringField(u'Телефон:',
                            validators = [Optional(),
                                          Length(max=config.MODEL_TELEPHONE,
                                                 message=u'Телефонный номер должен быть не более {0} символов'.format(config.MODEL_TELEPHONE))]) #inputtext (email, telephone, etc)
    archive = FileField(u'Файл:', validators=[Optional(), FileAllowed(['zip'], u'Файл должен быть zip-архивом!')])
    recaptcha = RecaptchaField()
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

class ProfileForm(Form):

    passwordold = PasswordField(u'Старый пароль:',
                                validators=[DataRequired(u'Для сохранения изменений необходимо указать текущий пароль'),
                                            Length(max=config.MODEL_PASSWORD, min=8,
                                                   message=u'Пароль должен быть длиной от 8 до {0} символов'.format(config.MODEL_PASSWORD))])
    password1 = PasswordField(u'Новый пароль:',
                              validators=[Optional(),
                                          Length(max=config.MODEL_PASSWORD, min=8,
                                                 message=u'Пароль должен быть длиной от 8 до {0} символов'.format(config.MODEL_PASSWORD)),
                                          EqualTo('password2', u'Новые пароли не совпадают')])
    password2 = PasswordField(u'Повтор пароля:', validators=[Optional()])
    email = StringField(u'Почта:',
                        validators = [Email(u'Неправильно введён Email'),
                                      Optional(),
                                      Length(max=config.MODEL_EMAIL,
                                             message=u'Email должен быть не более {0} символов'.format(config.MODEL_EMAIL))])
    apply_button = SubmitField(u'Сохранить')
    cancel_button = SubmitField(u'Отменить')

    def __init__(self, user, *args, **kwargs):
        super(ProfileForm, self).__init__(*args, **kwargs)
        self.user = user

    def validate(self):
        initial_validation = super(ProfileForm, self).validate()
        if not initial_validation:
            print "ProfileForm: initial_validation failed"
            return False

        if not self.user.check_password(self.passwordold.data):
            print "ProfileForm: invalid password"
            self.passwordold.errors.append(u'Неверный пароль')
            return False

        if self.password1.data and not self.user.password_is_strong(self.password1.data) :
            print "ProfileForm: weak password"
            self.password1.errors.append(u'Слабый пароль')
            return False

        print "ProfileForm: validation Ok"
        return True

class EditUserForm(Form) :

        password = PasswordField(u'Пароль:',
                                 validators=[Optional(),
                                             Length(max=config.MODEL_PASSWORD, min=8,
                                                    message=u'Пароль должен быть длиной от 8 до {0} символов'.format(config.MODEL_PASSWORD))])
        email = StringField(u'Почта:',
                            validators = [Email(u'Неправильно введён Email'),
                                          Optional(),
                                          Length(max=config.MODEL_EMAIL,
                                                 message=u'Email должен быть не более {0} символов'.format(config.MODEL_EMAIL))])
        role = SelectField(u'Роль:', validators = [DataRequired()])

        apply_button = SubmitField(u'Сохранить')
        cancel_button = SubmitField(u'Отменить')

        def __init__(self, *args, **kwargs):
          super(EditUserForm, self).__init__(*args, **kwargs)
          self.role.choices = User.roles_choices() #[('admin', u'Администратор'),('user', u'Пользователь')]
          #print self.role.choices

        def get_role(self) :
          return int(self.role.data)

        def set_role(self, role) :
          self.role.data = str(role)

        def validate(self):
          initial_validation = super(EditUserForm, self).validate()
          if not initial_validation:
            print "EditUserForm: initial_validation failed"
            return False
          if self.password.data and not User.password_is_strong(self.password.data) :
            print "EditUserForm: weak password"
            self.password.errors.append(u'Слабый пароль')
            return False
          print "EditUserForm: validation Ok"
          return True

class NewUserForm(EditUserForm):

        userid = StringField(u'Идентификатор:', 
                             validators = [DataRequired(u'Не введено имя пользователя'),
                                         Length(max=config.MODEL_USERNAME,
                                                message=u'Имя пользователя должно быть не более {0} символов'.format(config.MODEL_USERNAME))])
        first = StringField(u'Имя:', validators=[DataRequired()])
        last = StringField(u'Фамилия:', validators=[DataRequired()])

        def __init__(self, *args, **kwargs):
          super(NewUserForm, self).__init__(*args, **kwargs)
          self.password.validators = [ DataRequired(u'Для необходимо задать пароль'),
                                       Length(max=config.MODEL_PASSWORD, min=8,
                                              message=u'Пароль должен быть длиной от 8 до {0} символов'.format(config.MODEL_PASSWORD))]

