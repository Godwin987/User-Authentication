from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap5
from forms import Signin, Signup
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my_secret'
bootstrap = Bootstrap5(app)
db = SQLAlchemy()
login_manager = LoginManager()
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager.init_app(app)
db.init_app(app)
session = db.session


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

@login_manager.user_loader
def load_user(id):
    return session.get(entity=User, ident=int(id))


with app.app_context():
    # db.create_all()
    # @app.route('/signup', methods=['GET', 'POST'])
    # def home():
    #     form = Signup()
    #     if form.validate_on_submit():
    #         return "Successfully Logged in"
    #     return render_template('index.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = Signin()
        if form.validate_on_submit():
            user = User.query.filter_by(email=request.form.get('email')).first()
            if user:
                if check_password_hash(user.password, request.form.get('password')):
                    login_user(user)
                    return redirect(url_for('dashboard'))
        return render_template('login.html', form=form)

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        form = Signup()
        if form.validate_on_submit():
            new_user = User(
                name=request.form.get('name'),
                email=request.form.get('email'),
                password=generate_password_hash(request.form.get('password'))
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('dashboard'))
        return render_template('signup.html', form=form)

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('signup'))

    if __name__ == '__main__':
        app.run(debug=True)

echo "# User-Authentication" >> README.md
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/Godwin987/User-Authentication.git
git push -u origin main