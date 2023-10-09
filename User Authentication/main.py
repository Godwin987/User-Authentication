import os
import pathlib
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, request, abort, session, flash
from functools import wraps
from flask_bootstrap import Bootstrap5
from forms import Signin, Signup
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_oauth2 import ResourceProtector
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = "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"
# app.config.from_object('config')
bootstrap = Bootstrap5(app)
db = SQLAlchemy()
login_manager = LoginManager()
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager.init_app(app)
db.init_app(app)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1" # to allow Http traffic for local dev


# GOOGLE_CLIENT_ID = "170632269184-mkt1gklnaa4q25ah8tb60okeovsca3nf.apps.googleusercontent.com"
# client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

# flow = Flow.from_client_secrets_file(
#     client_secrets_file=client_secrets_file,
#     scopes=["https://www.googleapis.com/auth/userinfo.profile", 
#             "https://www.googleapis.com/auth/userinfo.email", "openid"],
#     redirect_uri="http://127.0.0.1:5000/callback"
# )
require_auth = ResourceProtector()
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
print(GOOGLE_CLIENT_ID)
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    client_kwargs={
        'scope': 'openid email profile'
    },
    server_metadata_url=CONF_URL
    )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

@login_manager.user_loader
def load_user(id):
    return db.session.get(entity=User, ident=int(id))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = dict(session).get('profile', None)
        # You would add a check here and usethe user id or something to fetch
        # the other data for that user/check if they exist
        if user:
            return f(*args, **kwargs)
        return 'You aint logged in, no page for u!'
    return decorated_function

# def login_is_required(function):
#     def wrapper(*args, **kwargs):
#         if "google_id" not in session:
#             return abort(401)  # Authorization required
#         else:
#             return function()

#     return wrapper


with app.app_context():
    # db.create_all()
    # @app.route('/signup', methods=['GET', 'POST'])
    # def home():
    #     form = Signup()
    #     if form.validate_on_submit():
    #         return "Successfully Logged in"
    #     return render_template('index.html', form=form)

    # @app.route("/authflow")
    # def authflow():
    #     authorization_url, state = flow.authorization_url()
    #     # print(session)
    #     session["state"] = state
    #     print(authorization_url)
    #     return redirect(authorization_url)

    # OAUTH FUNCTIONALITIES
    @app.route('/oauthlogin')
    def oauthlogin():
        redirect_uri = url_for('auth', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)


    @app.route('/auth')
    def auth():
        google = oauth.create_client('google')
        token = oauth.google.authorize_access_token()
        session['user'] = token['userinfo']['name']
        return redirect(url_for('dashboard'))


    @app.route('/oauthlogout')
    def oauthlogout():
        session.pop('user', None)
        return redirect(url_for('signup'))

    # NORMAL LOGIN FUNCTIONALITIES
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = Signin()
        if form.validate_on_submit():
            user = User.query.filter_by(email=request.form.get('email')).first()
            if user:
                if check_password_hash(user.password, request.form.get('password')):
                    login_user(user)
                    flash(message='Logged in successfully', category='success')
                    return redirect(url_for('dashboard'))
                else:
                    flash(message='Password is incorrect', category='danger')
            else:
                flash(message='Email does\'nt exist. You can signup for a new account', category='danger')
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
    
    # @app.route("/callback")
    # def callback():
    #     flow.fetch_token(authorization_response=request.url)

    #     if not session["state"] == request.args["state"]:
    #         abort(500)  # State does not match!

    #     credentials = flow.credentials
    #     request_session = requests.session()
    #     cached_session = cachecontrol.CacheControl(request_session)
    #     token_request = google.auth.transport.requests.Request(session=cached_session)

    #     id_info = id_token.verify_oauth2_token(
    #         id_token=credentials._id_token,
    #         request=token_request,
    #         audience=GOOGLE_CLIENT_ID
    #     )

    #     session["google_id"] = id_info.get("sub")
    #     session["name"] = id_info.get("name")
    #     return redirect("/dashboard")

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/logout')
    def logout():
        logout_user()
        flash(message='Logged out successfully', category='success')
        return redirect(url_for('signup'))

    if __name__ == '__main__':
        app.run(debug=True)

