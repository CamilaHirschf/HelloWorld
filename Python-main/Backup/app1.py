from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from datetime import timedelta, datetime
from db import User, db, reset_database
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm, Form
from flask_talisman import Talisman
from config import Config
import logging
import uuid
import os
import re

logging.basicConfig(filename='app.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)


class LoginForm(FlaskForm):
 username = StringField('Username')
 password = PasswordField('Password')

class MyForm(FlaskForm):
  username = StringField('Username', validators=[DataRequired()])
  password = PasswordField('Password', validators=[DataRequired()])
  submit = SubmitField('Submit')

app = Flask(__name__)

def create_app():
 app = Flask(__name__)
 
 Talisman(app)
 
 app.config['SECRET_KEY'] = 'Kns2o7Cb6hhRB0vSIwMj'
 #csrf = CSRFProtect(app)
 
 app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
 
 db.init_app(app)

 app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
 

 login_manager = LoginManager()
 login_manager.init_app(app)
 login_manager.login_view = 'login'
 login_manager.login_message = 'Por favor, inicie sesión para acceder a esta página.'
 login_manager.login_message_category = 'error'


 app.config.update(
 SESSION_COOKIE_SECURE=True,
 SESSION_COOKIE_HTTPONLY=True,
 SESSION_COOKIE_SAMESITE='Lax',
 )
 
 @app.errorhandler(404)
 def page_not_found(e):
    return render_template('error.html'), 404

 @app.route('/logout')
 @login_required
 def logout():
  logout_user()
  return redirect(url_for('login'))
                
 @app.route('/', methods=['GET', 'POST'])
 def index():
    logging.info('Index page accessed')
    form = MyForm()
    if form.validate_on_submit():
        logging.info('Form submitted successfully')
        return 'Success!'
    return render_template('login.html', form=form)

 @login_manager.user_loader
 def load_user(user_id):
   return User.query.get(int(user_id))

 @app.route('/register', methods=['GET', 'POST'])
 def register():
    form = MyForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            if User.query.filter_by(username=username).first() is not None:
                flash('Username already exists')
                return render_template('register.html', form=form)
            if password_check(password) != "Contraseña válida.":
                flash(password_check(password), category='error')
                return render_template('register.html', form=form)
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registered successfully', category='message')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


  
 def password_check(password):
    pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\+\=\%\$\@\!\^\*\?\&\~\#])[A-Za-z\d\+\=\%\$\@\!\^\*\?\&\~\#]{8,16}$')
    if pattern.match(password):
        return "Contraseña válida."
    else:
        return "La contraseña debe tener entre 8 y 16 caracteres, al menos una letra mayúscula, una letra minúscula, un número y un símbolo."


 @app.route('/login', methods=['GET', 'POST'])
 def login():
    form = MyForm()
    if request.method == 'POST':
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.', category='error')
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)


 @app.route('/dashboard')
 @login_required
 def dashboard():
    if current_user.is_authenticated:
        users = User.query.all()
        return render_template('dashboard.html', users=users)
    else:
        flash('Por favor, inicie sesión para acceder a esta página.', category='error')
        return redirect(url_for('login'))

 @app.after_request
 def apply_csp(response):
    nonce = os.urandom(16).hex()
    csp = f"default-src 'self'; script-src 'nonce-{nonce}'; object-src 'none'; base-uri 'none'"
    response.headers["Content-Security-Policy"] = csp
    response.headers["Nonce"] = nonce
    response.headers['Server'] = ''
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    session["ctx"] = {"request_id": str(uuid.uuid4())}
    app.logger.info('%s - "%s" "%s" "%s" "%s" "%s"', timestamp, request.method, request.path, response.status_code, request.remote_addr, str(session["ctx"]))
    return response
 
 
 stream_handler = logging.StreamHandler()
 app.logger.addHandler(stream_handler)

 def check_and_create_tables():
    with app.app_context():
       if not db.engine.has_table('user'):
          db.create_all()

 reset_database(app)

 return app
