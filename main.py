# python -m pip install -r requirements.txt

from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Table, ForeignKey, Column, or_, DateTime, Boolean
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from forms import AddBookForm, RegisterForm, LoginForm, PasswordResetForm, VerifyEmail
import smtplib
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os
import IP2Proxy
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7ggfbth6b'

load_dotenv()

MAIL_ADDRESS = os.environ.get("M_KEY")
MAIL_APP_PW = os.environ.get("P_KEY")

ckeditor = CKEditor(app)
Bootstrap5(app)

# FlaskLogin
login_manager = LoginManager()
login_manager.init_app(app)

#FlaskMail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("M_KEY")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("M_KEY")
app.config['MAIL_PASSWORD'] = os.getenv("P_KEY")
mail = Mail(app)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# Database creation
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lms.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

db1 = IP2Proxy.IP2Proxy()
db1.open("./IP2PROXY-LITE-PX1.BIN/IP2PROXY-LITE-PX1.BIN")

issued_books = Table('issued_books',
                     Base.metadata,
                     Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
                     Column('book_id', Integer, ForeignKey('LibraryBooks.id'), primary_key=True)
                     )


class Books(db.Model):
    __tablename__ = "LibraryBooks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    # available: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    available: Mapped[str] = mapped_column(String(100), nullable=False, default="Yes")
    issued_to = relationship("User", secondary=issued_books, back_populates="issued_books")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    issued_books = relationship("Books", secondary=issued_books, back_populates="issued_to")

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

with app.app_context():
    db.create_all()


# admin only decorator function
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # id = 1 for admin user
        if current_user.id != 1:
            return abort(403)

        return f(*args, **kwargs)

    return decorated_function



@app.route("/", methods=['GET'])
def home():
    return render_template('index.html')
#     global record
#     if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
#         ip = request.environ['REMOTE_ADDR']
#     else:
#         ip = request.environ['HTTP_X_FORWARDED_FOR']
#
#     if ip == '127.0.0.1':
#         ip = '127.0.0.1'
#
#     record = db1.get_all(ip)
#     if (record['country_short'] != '-'):
#         return redirect(url_for("error"), code=302)
#     else:
#         return redirect(url_for("main"), code=302)
#
#
#
# @app.route('/access-denied')
# def access_deny():
#     return render_template('index.html')



# register new users
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        # if email already in database
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            # already existing user
            flash("You're already registered. Login instead.")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for("home"))
    return render_template("register.html", form=form, current_user=current_user)


# login users
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))

        user = result.scalar()

        if not user:
            flash("The email is not registered. Check again.")
            return redirect(url_for('login'))
        # incorrect password
        elif not check_password_hash(user.password, password):
            flash('Incorrect password. Check again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))

    return render_template("login.html", form=form, current_user=current_user)


# @app.route('/reset-password', methods=["GET", "POST"])
# def password_reset():
#     form = PasswordResetForm()
#     if form.validate_on_submit():
#         result = db.session.execute(db.select(User).where(User.email == form.email.data))
#         user = result.scalar()
#
#         if user:
#             send_reset_password_email(user)
#
#         flash(
#             "Instructions to reset your password were sent to your email address,"
#             " if it exists in our system."
#         )
#
#         return redirect(url_for("password_reset"))
#
#     return render_template(
#         "passwordreset.html", title="Reset Password", form=form
#     )


# log out user
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


# display all books in the database
@app.route('/books')
def all_books():
    books = db.session.execute(db.select(Books).order_by(Books.id)).scalars()
    return render_template('books.html', books=books)


# add a new book in the database. for admin only.
@app.route("/new_book", methods=["GET", "POST"])
@admin_only
def add_new_book():
    form = AddBookForm()
    if form.validate_on_submit():
        new_book = Books(
            title=form.title.data,
            author=form.author.data,
        )
        db.session.add(new_book)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("add_book.html", form=form, current_user=current_user)


# edit a book. for admin only.
@app.route("/edit_book/<int:book_id>", methods=["GET", "POST"])
@admin_only
def edit_book(book_id):
    book = db.get_or_404(Books, book_id)
    edit_form = AddBookForm(
        title=book.title,
        author=book.author
    )
    if edit_form.validate_on_submit():
        book.title = edit_form.title.data
        book.author = edit_form.author.data
        db.session.commit()
        return redirect(url_for("all_books", book_id=book.id))
    return render_template("add_book.html", form=edit_form, is_edit=True, current_user=current_user)


# delete a book from database. for admin only.
@app.route("/delete/<int:book_id>")
@admin_only
def delete_book(book_id):
    book_to_delete = db.get_or_404(Books, book_id)
    db.session.delete(book_to_delete)
    db.session.commit()
    return redirect(url_for('all_books'))


# issue a book from the library.
@app.route("/issue_book/<int:book_id>/<int:user_id>")
def issue_book(book_id, user_id):
    user = db.get_or_404(User, user_id)
    book = db.get_or_404(Books, book_id)

    if book.available == "Yes":
        book.available = "No"
        user.issued_books.append(book)
        db.session.commit()
        return redirect(url_for('all_books'))
    else:
        return "Book is already issued."


# return an issued book to the library.
@app.route("/return_book/<int:book_id>/<int:user_id>")
def return_book(book_id, user_id):
    user = db.get_or_404(User, user_id)
    book = db.get_or_404(Books, book_id)

    if book in user.issued_books:
        book.available = "Yes"
        user.issued_books.remove(book)
        db.session.commit()
        return redirect(url_for('issued_books_by_user'))
    else:
        return "Book was not issued."


# shows all the books currently issued by the user.
@app.route("/mybooks")
def issued_books_by_user():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    user = db.get_or_404(User, current_user.id)
    return render_template('my_books.html', books=user.issued_books, user=user)


# shows all the users registered in the database.
@app.route('/users')
@admin_only
def all_users():
    users = User.query.all()
    return render_template('all_users.html', users=users)


# contact us page
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        data = request.form
        send_email(data["name"], data["email"], data["phone"], data["message"])
        return render_template("contact.html", msg_sent=True)
    return render_template("contact.html", msg_sent=False)


def send_email(name, email, phone, message):
    email_message = f"Subject:New Message\n\nName: {name}\nEmail: {email}\nPhone: {phone}\nMessage:{message}"
    with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
        connection.starttls()
        connection.login(MAIL_ADDRESS, MAIL_APP_PW)
        connection.sendmail(from_addr=MAIL_ADDRESS, to_addrs=MAIL_ADDRESS, msg=email_message)


# about us page
@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method=='POST':
        form = request.form
        search_value = form['search_string']

        if search_value == '':
            flash("Please enter something to search.")
            return redirect("/")
        else:
            search = "%{}%".format(search_value)
            results = Books.query.filter(or_(Books.title.like(search), Books.author.like(search))).all()

            if results:
                return render_template("search.html", books=results, pageTitle="searched books")
            else:
                flash("Searched book is not available. Try again!")
                return redirect("/")
    else:
        return redirect("/")


#mail for forgot password
def send_mail(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            link = url_for('reset_password', token=token, _external=True)
            template = f'<p>To reset your password, click the following link:</p><p><a href="{link}">{link}</a></p><p>This link will expire in 1 hour.</p>'
            send_mail(email, 'Password Reset Request', template)
            flash('A password reset link has been sent to your email.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email address not found.', 'danger')
    return render_template('forgot_password.html')


@app.route("/reset-password/<token>", methods=["GET", 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        user = User.query.filter_by(email=email).first()
        user.set_password(new_password)
        db.session.commit()
        flash("Your password has been updated. Login now!", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# @app.route('/verify/<email>', methods=['GET', 'POST'])
# def verify(email):
#     form = VerifyEmail()
#     user = User.query.filter_by(email=email).first()
#     if not user:
#         flash("No account is associated with that email address.", "warning")
#         return redirect(url_for('index'))



#     if user and form.validate_on_submit():
#         user.verify_token = secrets.token_hex(16)
#         user.verify_token_expiration = datetime.utcnow() + timedelta(hours=1)
#         db.session.commit()

#         verify_url = url_for('verify_account', token=user.verify_token, _external=True)

#         text_body = f"Click the link below to verify your account:\n\n{verify_url}"
#         html_body = render_template('verify_account_email.html', verify_url=verify_url)

#         message = Message('Verify account', recipients=[user.email], sender="mahiudemy7@gmail.com")
#         message.body = text_body
#         message.html = html_body
#         mail.send(message)

#         flash("An email with the verification link has been sent.", "success")

#     return render_template("verify_email.html", form=form, addr=user.email, form_login=LoginForm(),
#                            form_register=RegisterForm())


# @app.route('/verify-account/<token>', methods=['GET', 'POST'])
# def verify_account(token):
#     user = User.query.filter_by(verify_token=token).first()

#     if not user:
#         flash('This Link has expired.', 'warning')
#         return redirect(url_for('login'))

#     if user:
#         if datetime.utcnow() > user.verify_token_expiration:
#             flash('This Link has expired.', 'warning')
#             return redirect(url_for('login'))

#         user.verified = True
#         db.session.commit()
#         user.verify_token = None
#         db.session.commit()

#         flash('Your Account has been verified.', 'success')

#         if current_user.is_authenticated:
#             return redirect(url_for('index'))

#     return redirect(url_for("login"))



if __name__ == "__main__":
    print("MAIL_KEY:", os.getenv('M_KEY'))
    print("PASS_KEY:", os.getenv('P_KEY'))
    app.run(debug=True, port=5001)
