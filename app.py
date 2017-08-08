from flask import Flask, render_template, redirect, url_for,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import tempfile
import os.path
from flask.ext.scss import Scss

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////database.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + 'database.db'
Bootstrap(app)
Scss(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

array=['a','b','c','d','e','f','g','h','i','j']
counter=[0]*10
score=[0]

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

#class Question(FlaskForm):
    #answer = StringField('answer')

@app.route('/')
def index():
    return render_template('xy.html')


@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/leaderboard')
def leaderboard():
    return render_template('leaderboard.html')


@app.route('/xy')
def xy():
    return render_template('xy.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'

    return render_template('login.html', form=form)
    return render_template('blank.html')

@app.route('/qa', methods=['GET', 'POST'])
def qa():
	if request.method=='POST':
		ans = request.form['answer']
		if request.form.get('1'):
			if ans==array[0]:
				counter[0]+=1
				if counter[0]==1:
					score[0]+=1

		elif request.form.get('2'):
			if ans==array[1]:
				counter[1]+=1
				if counter[1]==1:
					score[0]+=1

		elif request.form.get('3'):
			if ans==array[2]:
				counter[2]+=1
				if counter[2]==1:
					score[0]+=1

		elif request.form.get('4'):
			if ans==array[3]:
				counter[3]+=1
				if counter[3]==1:
					score[0]+=1

		elif request.form.get('5'):
			if ans==array[4]:
				counter[4]+=1
				if counter[4]==1:
					score[0]+=1

		elif request.form.get('6'):
			if ans==array[5]:
				counter[5]+=1
				if counter[5]==1:
					score[0]+=1

		elif request.form.get('7'):
			if ans==array[6]:
				counter[6]+=1
				if counter[6]==1:
					score[0]+=1

		elif request.form.get('8'):
			if ans==array[7]:
				counter[7]+=1
				if counter[7]==1:
					score[0]+=1

		elif request.form.get('9'):
			if ans==array[8]:
				counter[7]+=1
				if counter[7]==1:
					score[0]+=1

		elif request.form.get('10'):
			if ans==array[9]:
				counter[8]+=1
				if counter[8]==1:
					score[0]+=1

		return str(score[0])
	
	return render_template('ques_ans.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first() is not None :
        	return '<h1>' + 'Username already exists. Choose another username.' + '</h1>'
        
        if User.query.filter_by(email=form.email.data).first() is not None :
        	return '<h1>' + 'Email-Id already exists. Choose another one.' + '</h1>'

        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return render_template('home.html', form=form)

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/blank')
def blank():
    return render_template('blank.html')


if __name__ == '__main__':
    app.run(debug=True)
