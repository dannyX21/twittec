from flask.ext.wtf import Form
from wtforms import StringField, TextAreaField, BooleanField, SelectField,\
    SubmitField
from wtforms.validators import Required, Length, Email, Regexp
from wtforms import ValidationError
from ..models import Role, User
from flask.ext.pagedown.fields import PageDownField


class NameForm(Form):
    name = StringField('Cual es tu nombre?', validators=[Required()])
    submit = SubmitField('Ok')


class EditProfileForm(Form):
    name = StringField('Nombre real', validators=[Length(0, 64)])
    location = StringField('Ubicacion', validators=[Length(0, 64)])
    about_me = TextAreaField('Acerca de mi')
    submit = SubmitField('Guardar')


class EditProfileAdminForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    username = StringField('Usuario', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Los nombres de usuario solo pueden contener letras, numeros, puntos y guion bajo.')])
    confirmed = BooleanField('Confirmado')
    role = SelectField('Rol', coerce=int)
    name = StringField('Nombre real', validators=[Length(0, 64)])
    location = StringField('Ubicacion', validators=[Length(0, 64)])
    about_me = TextAreaField('Acerca de mi')
    submit = SubmitField('Guardar')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('El Email ya esta registrado.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('El usuario ya existe.')


class PostForm(Form):
    body = PageDownField("Que piensas?", validators=[Required()])
    submit = SubmitField('Publicar')

class CommentForm(Form):
    body = StringField('', validators=[Required()])
    submit = SubmitField('Comentar')
