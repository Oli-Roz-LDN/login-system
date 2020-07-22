from flask import Flask, render_template, request, jsonify, json, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from flask_wtf import FlaskForm
from itsdangerous import URLSafeTimedSerializer
from oauthlib.oauth2 import WebApplicationClient
from oauth import OAuthSignIn
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, current_user, login_required, logout_user


app = Flask(__name__)
login = LoginManager(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SECRET_KEY'] = 'cairocoders-ednalan'
app.config['OAUTH_CREDENTIALS'] = {
    'facebook': {
        'id': 'YOUR_ID',
        'secret': 'YOUR_SECRET_KEY'
    },
    'google': {
        'id': 'YOUR_ID',
        'secret': 'YOUR_SECRET_KEY'
    },
}

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Main(db.Model):
	__tablename__ = 'main skill'

	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(60))

class Second(db.Model):
	__tablename__ = 'second skill'

	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(60))
	main_id = db.Column(db.Integer)
	id_two = db.Column(db.Integer)

class Third(db.Model):
	__tablename__ = 'third skill'

	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(60))
	secondid = db.Column(db.Integer)

class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	main = db.Column(db.String(60))
	second = db.Column(db.String(60))
	third = db.Column(db.String(60))
	other = db.Column(db.String(60))
	social_id = db.Column(db.String(64), nullable=True, unique=True)
	is_guru = db.Column(db.Boolean, default=False)
	email = db.Column(db.String(64), index=True, unique=True)
	username = db.Column(db.String(64), unique=True, index=True)
	firstname = db.Column(db.String(64))
	lastname = db.Column(db.String(64))
	location = db.Column(db.String(64))
	role_type = db.Column(db.String(64))
	international = db.Column(db.String(64))
	english = db.Column(db.String(64))
	other_language = db.Column(db.String(64))
	day_rate = db.Column(db.String(64), index=True)
	project_charge = db.Column(db.String(64), index=True)
	linkedin = db.Column(db.String(64), unique=True)
	twitter = db.Column(db.String(64), unique=True)
	github = db.Column(db.String(64), unique=True)
	marketing = db.Column(db.Boolean, default=False)

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password_hash, password)

class Form(FlaskForm):
    main = SelectField('main skill', choices=[])
    second = SelectField('second skill', choices=[])
    third = SelectField('third skill', choices=[])
    submit = SubmitField('REGISTER')

class BasicDetails(FlaskForm):
	firstname = StringField('First name')
	lastname = StringField('Last name')
	username = StringField('Username', validators=[DataRequired()])
	submit = SubmitField('Complete')

	def validate_username(self, username):
		user = User.query.filter_by(username=username.data).first()
		if user is not None:
			raise ValidationError('That username is taken. Please choose a different one.')

class UpdateClientAccount(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    submit = SubmitField('Update')

class candidateregistrationform(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
	marketing = BooleanField("Sign Up for marketing", default = False)
	submit = SubmitField('SIGN UP')
	
	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user is not None:
			raise ValidationError('That email address is already in use.')

class changeemail(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	submit = SubmitField('REGISTER')

class LocationForm(FlaskForm):
	location = StringField('Location', validators=[DataRequired()])
	role_type = SelectField('Location flex', choices=[('NC', 'Role Type - Please choose'), ('Remote Only', 'Remote Only'), ('Office Only', 'Office Only'), ('Remote & Office', 'Remote & Office')])
	international = SelectField('International Travel', choices=[('NC', 'International Travel?'), ('Yes', 'Yes'), ('No', 'No')])
	english = SelectField('English Fluency', choices=[('NC', 'English Fluency?'), ('Yes', 'Yes'), ('No', 'No')])
	other_language = SelectField('Other Languages', choices=[('NC', 'Other Languages?'), ('French', 'French'), ('German', 'German'), ('Spanish', 'Spanish'), ('Italian', 'Italian')])
	submit = SubmitField('Complete')

class OtherInfo(FlaskForm):
	day_rate = SelectField('Day Rate Expectations', choices=[('NC', 'Day Rate Expectations?'), ('€100-150', '€100-150'), ('€150-200', '€150-200'), ('€200-250', '€200-250'), ('€250-300', '€250-300'), ('€300-350', '€300-350'), ('€350-400', '€350-400'), ('€400-450', '€400-450')])
	project_charge = SelectField('Average Project Charge', choices=[('NC', 'Average Project Charge?'), ('€1000-1500', '€1000-1500'), ('€1500-2000', '€1500-2000'), ('€2000-2500', '€2000-2500'), ('€2500-3000', '€2500-3000'), ('€3000-3500', '€3000-3500'), ('€3500-4000', '€3500-4000'), ('€4000-4500', '€4000-4500')])
	linkedin = StringField('LinkedIn URL')
	twitter = StringField('Twitter Handle')
	github = StringField('GitHub')
	submit = SubmitField("Finish")

@login.user_loader
def load_user(id):
	return User.query.get(int(id))

@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('home'))

@app.route('/candidateregistration', methods=['GET', 'POST'])
def candidate_one():
	form = candidateregistrationform()
	if form.validate_on_submit():
		user = User(email=form.email.data.strip().lower(), marketing=form.marketing.data, is_guru=True)
		user.set_password(form.password.data)
		db.session.add(user)
		db.session.commit()

		login_user(user)


		flash('Congrats, you are now registered', 'success')
		return redirect('candidatewelcome')
	return render_template('candidate_one.html', title='Candidate Registration', form=form)

@app.route('/candidatewelcome')
def candidatewelcome():
	return render_template('candidatewelcome.html')


@app.route('/authorize/<provider>')
def oauth_authorize(provider):
	if not current_user.is_anonymous:
		return redirect(url_for('problems'))
	oauth = OAuthSignIn.get_provider(provider)
	return oauth.authorize()


@app.route('/callback/<provider>')
def oauth_callback(provider):
	if not current_user.is_anonymous:
		return redirect(url_for('problems'))
	oauth = OAuthSignIn.get_provider(provider)
	social_id, username, email = oauth.callback()
	if social_id is None:
		flash('Authentication failed.')
		return redirect(url_for('problems'))
	user = User.query.filter_by(social_id=social_id).first()
	if not user:
		user = User(social_id=social_id, username=username, email=email, is_guru=True)
		db.session.add(user)
		db.session.commit()
	login_user(user, True)
	return redirect(url_for('candidatewelcome'))

@app.route('/success')
def success():
 	return render_template('success.html')


@app.route('/second/<get_second>')
def secondbymain(get_second):
    second = Second.query.filter_by(main_id=get_second).all()
    secondArray = []
    for third in second:
        secondObj = {}
        secondObj['id'] = third.id
        secondObj['name'] = third.name
        secondArray.append(secondObj)
    return jsonify({'secondmain' : secondArray})

@app.route('/third/<get_third>')
def third(get_third):
    second_data = Third.query.filter_by(secondid=get_third).all()
    thirdArray = []
    for third in second_data:
        thirdObj = {}
        thirdObj['id'] = third.id
        thirdObj['name'] = third.name
        thirdArray.append(thirdObj)
    return jsonify({'thirdlist' : thirdArray})

@app.route('/problems')
def problems():
	return render_template('problems.html')

@app.route('/')
def home():
	return render_template('home.html')

@app.route('/candidate')
def candidate():
	return render_template('candidate.html')

@app.route("/changeemail", methods=['GET', 'POST'])
@login_required
def changeemail():
    form = changeemail()
    if form.validate_on_submit():
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect('success.html')
    elif request.method == 'GET':
        form.email.data = current_user.email
    return render_template('changeemail.html', title='Account', form=form)


@app.route("/clientaccount", methods=['GET', 'POST'])
@login_required
def clientaccount():
    form = UpdateClientAccount()
    if current_user.is_guru != True:
        return redirect('/problems')
    if form.validate_on_submit():
        current_user.email = form.email.data
        current_user.username = form.username.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect('success')
    elif request.method == 'GET':
        form.email.data = current_user.email
    return render_template('clientaccount.html', title='Client Account', form=form)

@app.route('/candidateregistrationtwo', methods=['GET', 'POST'])
@login_required
def index():
    form = Form()
    form.main.choices = [(main.id, main.name) for main in Main.query.all()]
    

    if request.method == 'POST':

    	third = Third.query.filter_by(id=form.third.data).first()
    	main = Main.query.filter_by(id=form.main.data).first()
    	second = Second.query.filter_by(id=form.second.data).first()
    	current_user.third = form.third.data
    	current_user.main = form.main.data
    	current_user.second = form.second.data
    	db.session.commit()
    	return redirect('candidateregistrationthree')
    return render_template('index.html', form=form)

@app.route('/candidateregistrationone', methods=['GET', 'POST'])
@login_required
def candidateregistrationone():
	form = BasicDetails()

	if form.validate_on_submit():
		current_user.firstname = form.firstname.data
		current_user.lastname = form.lastname.data
		current_user.username = form.username.data
		db.session.commit()
		return redirect('candidateregistrationtwo')
	return render_template('candidateregone.html', form=form)

@app.route('/candidateregistrationthree', methods=['GET', 'POST'])
@login_required
def candidateregistrationthree():
	form = LocationForm()

	if form.validate_on_submit():
		current_user.location = form.location.data
		current_user.role_type = form.role_type.data
		current_user.international = form.international.data
		current_user.english = form.english.data
		current_user.other_language = form.other_language.data
		db.session.commit()
		return redirect('candidateregistrationfour')
	return render_template('candidateregthree.html', form=form)

@app.route('/candidateregistrationfour', methods=['GET', 'POST'])
@login_required
def candidateregistrationfour():
	form = OtherInfo()

	if form.validate_on_submit():
		current_user.day_rate = form.day_rate.data
		current_user.project_charge = form.project_charge.data
		current_user.linkedin = form.linkedin.data
		current_user.twitter = form.twitter.data
		current_user.github = form.github.data
		db.session.commit()
		return redirect('success')
	return render_template('candidateregfour.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
