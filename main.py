from flask import Flask, render_template, redirect, url_for, flash, request, send_file, make_response
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length
from sqlalchemy.ext.mutable import MutableDict
from werkzeug.utils import secure_filename

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.mutable import Mutable
import zlib
from flask import request

import os

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


class CompressedMutable(MutableDict):

	def __bytes__(self):
		# Convert the value to bytes
		if self.value is not None:
			return bytes(self.value)
		return b""

	@classmethod
	def coerce(cls, key, value):
		if not isinstance(value, cls):
			if isinstance(value, bytes):
				return cls(value)
			return MutableDict.coerce(key, value)
		else:
			return value


class File(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	filename = db.Column(db.String(256))
	data = db.Column(db.LargeBinary, nullable=False)
	compressed_data = db.Column(CompressedMutable.as_mutable(db.LargeBinary))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	user = db.relationship('User', backref=db.backref('files', lazy=True))


class Point(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	x = db.Column(db.Float, nullable=False)
	y = db.Column(db.Float, nullable=False)


class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable=False, unique=True)
	password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
	username = StringField(validators=[InputRequired(),
	                                   Length(min=4, max=20)],
	                       render_kw={"placeholder": "Username"})

	password = PasswordField(validators=[InputRequired(),
	                                     Length(min=8, max=20)],
	                         render_kw={"placeholder": "Password"})

	submit = SubmitField('Register')

	def validate_username(self, username):
		existing_user_username = User.query.filter_by(username=username.data).first()
		if existing_user_username:
			raise ValidationError(
			 'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
	username = StringField(validators=[InputRequired(),
	                                   Length(min=4, max=20)],
	                       render_kw={"placeholder": "Username"})

	password = PasswordField(validators=[InputRequired(),
	                                     Length(min=8, max=20)],
	                         render_kw={"placeholder": "Password"})

	remember = BooleanField('Remember Me')  # Added remember field

	submit = SubmitField('Login')


# Create database tables
with app.app_context():
	db.create_all()


@app.route('/')
def home():
	return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('dashboard'))

	form = LoginForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user and bcrypt.check_password_hash(user.password, form.password.data):
			login_user(user, remember=form.remember.data)
			return redirect(url_for('dashboard'))
		else:
			flash('Login unsuccessful. Please check your username and password.',
			      'danger')

	return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
	if request.method == 'POST':
		x = request.form.get('x')
		y = request.form.get('y')

		# Create a new point and save it to the database
		point = Point(x=x, y=y)
		db.session.add(point)
		db.session.commit()

	# Retrieve all points from the database
	points = Point.query.all()
	points_data = [{'x': point.x, 'y': point.y} for point in points]

	# Retrieve all files from the database for the current user
	files = File.query.filter_by(user=current_user).all()

	return render_template('dashboard.html', files=files, points=points_data)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))


@app.route('/messagepage')
def messagepage():
	return render_template('messagepage.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm()

	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data
		hashed_password = bcrypt.generate_password_hash(password)
		existing_user_username = User.query.filter_by(username=username).first()
		if existing_user_username:
			flash('That username already exists. Please choose a different one.',
			      'danger')
		else:
			new_user = User(username=username, password=hashed_password)
			db.session.add(new_user)
			db.session.commit()
			flash('Registration successful. Please login.', 'success')
			return redirect(url_for('login'))

	return render_template('register.html', form=form)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'GET':
        return render_template('upload.html')
    elif request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_data = file.read()

            new_file = File(filename=filename, data=file_data, user=current_user)
            db.session.add(new_file)
            db.session.commit()
			
            return 'File uploaded successfully.'

        else:
            return 'No file selected.'


@app.route('/view/<int:file_id>')
@login_required
def view_file(file_id):
    file = File.query.filter_by(id=file_id, user=current_user).first()
    if file:
        # Create a response with the file data
        response = make_response(file.data)
        response.headers.set('Content-Disposition', 'attachment', filename=file.filename)
        return response
    else:
        return 'File not found or unauthorized access'
      
@app.route('/addBusiness')
def add_business():
    return render_template('addBusiness.html')
@app.route('/viewBusiness')
def view_business():
    return render_template('viewBusiness.html')
if __name__ == '__main__':
	app.run(host='0.0.0.0', port=81)
