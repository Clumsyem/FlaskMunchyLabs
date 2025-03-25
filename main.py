from flask import Flask, render_template, url_for, redirect, session, request, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import matplotlib
import matplotlib.pyplot as plt
import csv
import io
import base64

matplotlib.use('Agg')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'BMMjvhROy5RTnekYyx1eiZuVsnjU5Jbu'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20),nullable=False, unique=True)
	password = db.Column(db.String(80),nullable=False)

class Food(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(40))
	weight = db.Column(db.Float, nullable=False, default=0)
	calories = db.Column(db.Integer, nullable=False, default=0)

	def __init__(self, name, weight, calories):
		self.name = name
		self.weight = weight
		self.calories = calories

class RegisterForm(FlaskForm):
	username = StringField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "Username"})
	password = PasswordField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "Password"})

	submit = SubmitField("Register")

	def validate_username(self, username):
		existing_user_username = User.query.filter_by(username=username.data).first()
		if existing_user_username:
			raise ValidationError("That username already exists, please select a different username.")

class LoginForm(FlaskForm):
	username = StringField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "Username"})
	password = PasswordField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "Password"})

	submit = SubmitField("Login")

@app.route("/home")
@app.route("/")
def home():
	return render_template("index.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))  # Redirect to dashboard if logged in

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)  # Log in the user
                return redirect(url_for("dashboard"))  # Redirect to dashboard after login

    return render_template("login.html", form=form)

@app.route("/dashboard", methods = ['GET', 'POST'])
@login_required
def dashboard():
	name = None
	weight = None
	calories = None

	if request.method == "POST":
		name = request.form.get("name")
		weight = request.form.get("weight")
		calories = request.form.get("calories")

		new_food = Food(name=name, weight=float(weight), calories=int(calories))
		db.session.add(new_food)
		db.session.commit()

	return render_template("dashboard.html", name=name, weight=weight, calories=calories)

@app.route("/logout", methods = ['GET', 'POST'])
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))

@app.route("/register", methods = ['GET', 'POST'])
def register():
	form = RegisterForm()

	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data)
		new_user = User(username=form.username.data, password=hashed_password)
		db.session.add(new_user)
		db.session.commit()
		return redirect(url_for('login'))

	return render_template("register.html", form=form)

#@app.route("/food_list", methods=['GET'])
#def food_list():
#    foods = Food.query.all() 
#    return render_template("food_list.html", foods=foods)

@app.route("/download_foods", methods=['GET'])
@login_required
def download_foods():
    foods = Food.query.all()
    output = io.StringIO()
    csv_writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    csv_writer.writerow(['ID', 'Name', 'Weight', 'Calories'])
    for food in foods:
        csv_writer.writerow([food.id, food.name, food.weight, food.calories])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={"Content-Disposition": "attachment;filename=foods.csv"})

@app.route("/food_list", methods=['GET'])
def food_list():
    foods = Food.query.all()

    calories = [food.calories for food in foods]

    plt.figure(figsize=(10, 6))
    plt.hist(calories, bins=10, color='skyblue', edgecolor='black')
    plt.title('Distribution of Calories in Food Items')
    plt.xlabel('Calories (kcal)')
    plt.ylabel('Frequency')
    plt.grid(axis='y', alpha=0.75)

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    image_base64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close() 
    return render_template("food_list.html", foods=foods, image=image_base64)

if __name__ == "__main__":
	with app.app_context():
		db.create_all()
	app.run(debug=True)