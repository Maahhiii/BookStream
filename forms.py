from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email


# form for adding a book.
class AddBookForm(FlaskForm):
    title = StringField("Book Title", validators=[DataRequired()])
    author = StringField("Book Author", validators=[DataRequired()])
    submit = SubmitField("Add Book")


# form for registering users
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Up")


# form for login
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class PasswordResetForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    submit = SubmitField("Submit")


class VerifyEmail(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    recaptcha = RecaptchaField()
    submit = SubmitField("Send Verification Email")