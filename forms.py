from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, HiddenField, FloatField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=5, message='用户名至少需要5个字符'),
        Regexp('^[a-zA-Z0-9]+$', message='用户名只能包含字母和数字')
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='密码至少需要8个字符'),
        Regexp('^(?=.*[a-zA-Z])(?=.*[0-9])[a-zA-Z0-9]+$',
               message='密码必须包含字母和数字，且不能包含特殊字符')
    ])
    captcha = StringField('Captcha', validators=[DataRequired()])
    captcha_hidden = HiddenField()

class PostForm(FlaskForm):
    title = StringField('商品名称', validators=[DataRequired()])
    body = TextAreaField('商品描述', validators=[DataRequired()])
    price = FloatField('价格', validators=[DataRequired()])
    status = SelectField('状态', choices=[
        ('available', '可购买'),
        ('reserved', '已预订'),
        ('sold', '已售出')
    ], default='available')
class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    captcha = StringField('Captcha', validators=[DataRequired()])
    captcha_hidden = HiddenField()
    submit = SubmitField('发送重置邮件')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('重置密码')

class SearchForm(FlaskForm):
    query = StringField('搜索', validators=[DataRequired()])