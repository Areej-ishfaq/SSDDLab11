from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Email, Length, Regexp, ValidationError, EqualTo
from flask_bcrypt import Bcrypt
from sqlalchemy.sql import text
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secure-random-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contacts.db'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_PERMANENT'] = True

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
csrf.init_app(app)

# ---- Models ----
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)

# ---- Validators ----
def no_sql_injection(form, field):
    forbidden = ['SELECT', 'INSERT', 'DELETE', 'UPDATE', 'DROP', '--', ';']
    value = field.data.upper()
    if any(keyword in value for keyword in forbidden):
        raise ValidationError('Invalid input.')

def safe_name(form, field):
    if not re.match(r'^[a-zA-Z\s\.\-]+$', field.data):
        raise ValidationError('Name contains invalid characters.')

# ---- Forms ----
class LoginForm(FlaskForm):
    form_type = HiddenField(default='login')
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150), no_sql_injection])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    form_type = HiddenField(default='register')
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=150),
        no_sql_injection
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8)
    ])
    confirm = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

class AddContactForm(FlaskForm):
    form_type = HiddenField(default='add_contact')
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=150), safe_name, no_sql_injection])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[Length(max=50)])
    submit = SubmitField('Add Contact')

class ContactUsForm(FlaskForm):
    form_type = HiddenField(default='contact_us')
    name = StringField('Your name', validators=[DataRequired(), Length(min=2, max=150), safe_name, no_sql_injection])
    email = StringField('Your email', validators=[DataRequired(), Email()])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=5)])
    submit = SubmitField('Send Message')

# ---- Routes ----
@app.route('/', methods=['GET', 'POST'])
def index():
    registration_form = RegistrationForm()
    login_form = LoginForm()
    add_contact_form = AddContactForm()
    contact_us_form = ContactUsForm()

    login_error = None
    registration_error = None
    add_contact_success = False
    contact_us_success = False

    if request.method == 'POST':
        form_type = request.form.get('form_type')

        if form_type == 'login':
            if login_form.validate_on_submit():
                stmt = text("SELECT * FROM user WHERE username = :username")
                result = db.engine.execute(stmt, {"username": login_form.username.data}).fetchone()
                if result:
                    hashed_pw = result['password_hash']
                    if bcrypt.check_password_hash(hashed_pw, login_form.password.data):
                        session['username'] = result['username']
                        flash('Logged in successfully.', 'success')
                        return redirect(url_for('index'))
                    else:
                        login_error = 'Invalid username or password.'
                else:
                    login_error = 'Invalid username or password.'

        elif form_type == 'register':
            if registration_form.validate_on_submit():
                existing_user = User.query.filter_by(username=registration_form.username.data).first()
                if existing_user:
                    registration_error = 'Username already exists'
                else:
                    hashed_pw = bcrypt.generate_password_hash(registration_form.password.data).decode('utf-8')
                    new_user = User(
                        username=registration_form.username.data,
                        password_hash=hashed_pw
                    )
                    db.session.add(new_user)
                    db.session.commit()
                    flash('Registration successful! Please login.', 'success')
                    return redirect(url_for('index'))

        elif form_type == 'add_contact':
            if add_contact_form.validate_on_submit():
                new_contact = Contact(
                    name=add_contact_form.name.data,
                    email=add_contact_form.email.data,
                    phone=add_contact_form.phone.data
                )
                db.session.add(new_contact)
                db.session.commit()
                add_contact_success = True
                flash('Contact added successfully.', 'success')

        elif form_type == 'contact_us':
            if contact_us_form.validate_on_submit():
                new_message = Message(
                    name=contact_us_form.name.data,
                    email=contact_us_form.email.data,
                    message=contact_us_form.message.data
                )
                db.session.add(new_message)
                db.session.commit()
                contact_us_success = True
                flash('Your message has been sent!', 'success')

    contacts = Contact.query.all()
    return render_template('index.html',
                         registration_form=registration_form,
                         login_form=login_form,
                         add_contact_form=add_contact_form,
                         contact_us_form=contact_us_form,
                         login_error=login_error,
                         registration_error=registration_error,
                         add_contact_success=add_contact_success,
                         contact_us_success=contact_us_success,
                         contacts=contacts)

# ---- Error Handlers ----
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# ---- DB Setup & Default Admin User ----
@app.before_request
def create_default_user():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        hashed_pw = bcrypt.generate_password_hash('admin123').decode('utf-8')
        new_user = User(username='admin', password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=False)