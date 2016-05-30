# -*- coding: utf-8 -*-

from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('Contraseña', validators=[Required()])
    remember_me = BooleanField('Recordar')
    submit = SubmitField('Log In')


class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                           Email()])
    username = StringField('Usuario', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Los nombres de usuario solo deben contener letras, numeros, puntos y guion bajo.')])
    password = PasswordField('Contraseña', validators=[
        Required(), EqualTo('password2', message='Las contraseñas deben coincidir.')])
    password2 = PasswordField('Confirmar contraseña', validators=[Required()])
    submit = SubmitField('Registrar')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('El email ya esta registrado.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('El usuario ya esta siendo utilizado.')


class ChangePasswordForm(Form):
    old_password = PasswordField('Contraseña anterior', validators=[Required()])
    password = PasswordField('Nueva contraseña', validators=[
        Required(), EqualTo('password2', message='Las contraseñas deben coincidir.')])
    password2 = PasswordField('Confirmar nueva contraseña', validators=[Required()])
    submit = SubmitField('Actualizar')


class PasswordResetRequestForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField('Restaurar contraseña')


class PasswordResetForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('Nueva contraseña', validators=[
        Required(), EqualTo('password2', message='Las contraseñas deben coincidir.')])
    password2 = PasswordField('Confirmar contraseña', validators=[Required()])
    submit = SubmitField('Restaurar contraseña')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('Email desconocido.')


class ChangeEmailForm(Form):
    email = StringField('Nuevo Email', validators=[Required(), Length(1, 64),
                                                 Email()])
    password = PasswordField('Contraseña', validators=[Required()])
    submit = SubmitField('Actualizar Email')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('El Email ya esta registrado.')
