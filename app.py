from flask import Flask, render_template, url_for, redirect
from flask_login import login_user, login_required, logout_user, UserMixin, LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Email, Length, InputRequired, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = "SECRET_KEY"
db = SQLAlchemy(app)
login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.filter_by(id=user_id).first()


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired("обовязкове поле до заповнення")])
    email = StringField(validators=[Email("некоректний емейл"), InputRequired("обовязкове поле до заповнення")])
    password = PasswordField(validators=[DataRequired(), Length(min=4, max=40)])
    password_reply = PasswordField(validators=[EqualTo('password', message="Паролі не співпадають!"), InputRequired("Обов'язкове до заповнення!"), Length(min=4, max=40)])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired()])
    password = PasswordField(validators=[InputRequired()])
    remember_me = BooleanField("Запам'ятати мене", default=False)
    submit = SubmitField("Залогінитись")


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(40), nullable=False)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            hash = generate_password_hash(form.password.data)
            u = Users(username=form.username.data, email=form.email.data, password=hash)

            db.session.add(u)
            db.session.flush()
            db.session.commit()

        except:
            db.session.rollback()
            print("помилка при записі")

    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username and password:
            user = Users.query.filter_by(username=username).first()

            if user and check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('index'))

            else:
                return "неправельний пароль або пошта"
        else:
            return 'будь ласка введіть правильний пароль'
    else:
        return render_template('login.html', form=form)


@app.route('/profile/<int:id>')
@login_required
def profile(id):
    info = []
    try:
        info = Users.query.get(id)

    except:
        print("помилка при читанні")
    return render_template("profile.html", list=info)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_page'))


if __name__ == "__main__":
    app.run(debug=True)