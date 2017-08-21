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
#from passlib.hash import sha256_crypt
from flask.ext.bcrypt import Bcrypt
from flask_login import current_user
#from api import Query

bc = Bcrypt(None)
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
#counter=[0]*10
#points=[0]
#bools=[False]*10

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    score = db.Column(db.Integer)
    q1 = db.Column(db.Integer)
    q2 = db.Column(db.Integer)
    q3 = db.Column(db.Integer)
    q4 = db.Column(db.Integer)
    q5 = db.Column(db.Integer)
    q6 = db.Column(db.Integer)
    q7 = db.Column(db.Integer)
    q8 = db.Column(db.Integer)
    q9 = db.Column(db.Integer)
    q10 = db.Column(db.Integer)
    q11 = db.Column(db.Integer)
    q12 = db.Column(db.Integer)
    q13 = db.Column(db.Integer)
    q14 = db.Column(db.Integer)
    q15 = db.Column(db.Integer)
    q16 = db.Column(db.Integer)
    q17 = db.Column(db.Integer)
    q18 = db.Column(db.Integer)
    q19 = db.Column(db.Integer)
    q20 = db.Column(db.Integer)
	

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
    
@app.route('/')
def index():
    return render_template('xy.html')


@app.route('/home')
def home():
    return render_template('home.html')

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

@app.route('/qa', methods=['GET', 'POST'])
def qa():
	if request.method=='POST':
		
		ans = request.form['answer']
		user = User.query.filter_by(username=current_user.username).first()
		#h = generate_password_hash('7.4', method='sha256')
		b = 'sha256$xaL6YZBn$f69a2e4bf44292f7b8fec7838eb86f47ce6199474afae260b3101a5701be24cc'
		a2 = 'sha256$sfDpsQzW$eeb7eaea54bb73ec9ebca295e3144e4bcbf4bb8cf0ed94677be42a8a35e4abb4'
		a3 = 'sha256$zuYDaceG$7d5eb73c31314b493b868c09771fb6406c23c2db77b8024cd4e55b988df2c081'
		a4 = 'sha256$jUlSRWgz$a37547990a573f228c94351a74362ef9b349b9cb6d2d22482ed82c087192061f'
		a5 = 'sha256$5Wq4yj45$9e8703689f1a6ec208f8230bae4f2d730eca05313e40bd113c6b6edb2c104bb0'

		if request.form.get('1'):
			user = User.query.filter_by(username=current_user.username)
			user = User.query.filter_by(username=current_user.username).update(dict(q1=1))
			db.session.commit()
			if current_user.q1==1:
				user = User.query.filter_by(username=current_user.username)
				user = User.query.filter_by(username=current_user.username).update(dict(score=5))
				db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return.html')

		elif request.form.get('2'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q2 != 1:
				user = User.query.filter_by(username=current_user.username).update(dict(q2=-1))
				db.session.commit()
			if check_password_hash(a2,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q2=1))
				db.session.commit()
				if current_user.q2==1:
					user = User.query.filter_by(username=current_user.username)
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('3'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q3!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q3=-1))
				db.session.commit()
			if check_password_hash(a3,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q3=1))
				db.session.commit()
				if current_user.q3==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('4'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q4!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q4=-1))
				db.session.commit()
			if check_password_hash(a4,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q4=1))
				db.session.commit()
				if current_user.q4==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('5'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q5!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q5=-1))
				db.session.commit()
			if check_password_hash(a5,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q5=1))
				db.session.commit()
				if current_user.q5==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		'''elif request.form.get('6'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q6!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q6=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q6=1))
				db.session.commit()
				if current_user.q6==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('7'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q7!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q7=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q7=1))
				db.session.commit()
				if current_user.q7==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('8'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q8!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q8=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q8=1))
				db.session.commit()
				if current_user.q8==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('9'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q9!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q9=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q9=1))
				db.session.commit()
				if current_user.q9==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')


		elif request.form.get('10'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q10!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q10=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q10=1))
				db.session.commit()
				if current_user.q10==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			#return h
			return render_template('qa_return2.html')

		elif request.form.get('11'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q11!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q11=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q11=1))
				db.session.commit()
				if current_user.q11==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')
			
		elif request.form.get('12'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q12!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q12=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q12=1))
				db.session.commit()
				if current_user.q12==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('13'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q13!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q13=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q13=1))
				db.session.commit()
				if current_user.q13==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('14'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q14!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q14=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q14=1))
				db.session.commit()
				if current_user.q14==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('15'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q15!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q15=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q15=1))
				db.session.commit()
				if current_user.q15==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('16'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q16!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q16=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q16=1))
				db.session.commit()
				if current_user.q16==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('17'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q17!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q17=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q17=1))
				db.session.commit()
				if current_user.q17==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('18'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q18!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q18=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q18=1))
				db.session.commit()
				if current_user.q18==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('19'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q19!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q19=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q19=1))
				db.session.commit()
				if current_user.q19==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')

		elif request.form.get('20'):
			user = User.query.filter_by(username=current_user.username)
			if current_user.q20!=1:
				user = User.query.filter_by(username=current_user.username).update(dict(q20=-1))
				db.session.commit()
			if check_password_hash(b,request.form['answer']):
				user = User.query.filter_by(username=current_user.username).update(dict(q20=1))
				db.session.commit()
				if current_user.q20==1:
					user = User.query.filter_by(username=current_user.username).update(dict(score=5))
					db.session.commit()
				return render_template('qa_return.html')
			return render_template('qa_return2.html')'''

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
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, score=0)# q1=0, q2=0, q3=0, q4=0, q5=0, q6=0, q7=0, q8=0, q9=0, q10=0, q11=0, q12=0, q13=0, q14=0, q15=0, q16=0, q17=0, q18=0, q19=0, q20=0)
        db.session.add(new_user)
        db.session.commit()

        return render_template('home.html', form=form)

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
	sc = 0
	if current_user.q1 == 1:
		sc += 5
	if current_user.q2 == 1:
		sc += 5
	if current_user.q3 ==1:
		sc += 5
	if current_user.q4 ==1:
		sc += 5
	if current_user.q5 ==1:
		sc += 5
	if current_user.q6 ==1:
		sc += 5
	if current_user.q7 ==1:
		sc += 5
	if current_user.q8 ==1:
		sc += 5
	if current_user.q9 ==1:
		sc += 10
	if current_user.q10 ==1:
		sc += 10
	if current_user.q11 ==1:
		sc += 10
	if current_user.q12 ==1:
		sc += 10
	if current_user.q13 ==1:
		sc += 10
	if current_user.q14 ==1:
		sc += 10
	if current_user.q15 ==1:
		sc += 10
	if current_user.q16 ==1:
		sc += 15
	if current_user.q17 ==1:
		sc += 15
	if current_user.q18 ==1:
		sc += 15
	if current_user.q19 ==1:
		sc += 15
	if current_user.q20 ==1:
		sc += 15
	current_user.score = sc
	return render_template('dashboard.html', name=current_user.username, ques1=current_user.q1, ques2=current_user.q2, ques3=current_user.q3, ques4=current_user.q4, ques5=current_user.q5, ques6=current_user.q6, ques7=current_user.q7, ques8=current_user.q8, ques9=current_user.q9, ques10=current_user.q10, ques11=current_user.q11, ques12=current_user.q12, ques13=current_user.q13, ques14=current_user.q14, ques15=current_user.q15, ques16=current_user.q16, ques17=current_user.q17, ques18=current_user.q18, ques19=current_user.q19, ques20=current_user.q20, scores=current_user.score)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/blank')
def blank():
    return render_template('blank.html')


if __name__ == '__main__':
    app.run()
