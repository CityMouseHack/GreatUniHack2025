from flask import Flask, render_template, request, redirect, url_for, flash,session
from flask_login import LoginManager , current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

# App initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key' # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions

import firebase_admin
from firebase_admin import credentials
from firebase_admin import db as fbdb
import dotenv
import os

dotenv.load_dotenv()
CRED=os.environ.get("CRED")
URL=os.environ.get("URL")

cred = credentials.Certificate(CRED)

firebase_admin.initialize_app(cred, {
    'databaseURL': URL
})

ref = fbdb.reference('/')

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = models.finduser(fbdb.reference("users").get(),username)
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class MessageForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

# Routes
@app.route('/')
def index():
    if "user" in session:
        return redirect(url_for('conversations'))
    return redirect(url_for('login'))

import models
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = models.makeuser(None,form.username.data,form.password.data)
        # userref = ref.child("users").push(user)
        # print(userref.key)
        fbdb.reference("users/"+form.username.data).set(user)
        
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if "user" in session:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        password=models.finduser(fbdb.reference("users").get(),form.username.data)
        # user = User.query.filter_by(username=form.username.data).first()
        if password is None or not check_password_hash(password,form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        # login_user(user, remember=True)
        flash("Logged in!")
        session["user"]=form.username.data
        return redirect(url_for('index'))
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    session.pop("user",None)
    flash("Logged out!")
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if "user" in session:
        return render_template('profile.html', title='Profile',user=session["user"])
    else:
        return redirect(url_for('login'))

@app.route('/conversations')
def conversations():
    # Find all users the current user has had a conversation with
    # sent_messages = db.session.query(Message.recipient_id).filter(Message.sender_id == current_user.id)
    # received_messages = db.session.query(Message.sender_id).filter(Message.recipient_id == current_user.id)
    
    # user_ids = set([item[0] for item in sent_messages.all()] + [item[0] for item in received_messages.all()])
    
    # users = User.query.filter(User.id.in_(user_ids)).all()
    user=models.User()
    user.id=0
    user.username="test"
    user.password_hash="fefef"
    users=[]
    users.append(user)
    loggedin=False
    if "user" in session:
        loggedin=True
    
    return render_template('conversations.html', users=users, title='Conversations',loggedin=loggedin)

@app.route('/new_conversation', methods=['POST'])

def new_conversation():
    username = request.form.get('username')
    # user = User.query.filter_by(username=username).first()
    user=False
    if user:
        if user.id == current_user.id:
            flash('You cannot start a conversation with yourself.', 'danger')
            return redirect(url_for('conversations'))
        return redirect(url_for('chat', username=user.username))
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('conversations'))

@app.route('/chat/<username>', methods=['GET', 'POST'])
@login_required
def chat(username):
    # partner = User.query.filter_by(username=username).first_or_404()
    # if partner == current_user:
    #     flash("You cannot chat with yourself.")
    #     return redirect(url_for('conversations'))

    # form = MessageForm()
    # if form.validate_on_submit():
    #     msg = Message(sender_id=current_user.id,
    #                   recipient_id=partner.id,
    #                   content=form.message.data)
    #     db.session.add(msg)
    #     db.session.commit()
    #     return redirect(url_for('chat', username=username))

    # messages = Message.query.filter(
    #     or_(
    #         (Message.sender_id == current_user.id) & (Message.recipient_id == partner.id),
    #         (Message.sender_id == partner.id) & (Message.recipient_id == current_user.id)
    #     )
    # ).order_by(Message.timestamp.asc()).all()

    # return render_template('chat.html', title=f'Chat with {username}',
    #                        form=form, partner=partner, messages=messages)
    return render_template("register.html")

if __name__ == '__main__':
    # with app.app_context():
    #     db.create_all()
    app.run(debug=True)