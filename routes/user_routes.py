"""
 Importing Packages
"""
import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from firebase_admin import auth
import logging
import jwt
from flask import Blueprint, request, jsonify, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from models import db, User

load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
user_routes = Blueprint('user_routes', __name__)

def send_email_verification(email, verification_link):
    """
        Sending email verification
    """
    try:
        send_email(email, "Email Verification", f"Thanks for creating an account."
                   f" Click this below to verify your email address and sign in to your account.\n\n {verification_link}")
        logging.info("Email verification link sent to %s", email)
    except Exception as e:
        logging.error('Failed to send email verification %s', e)

def send_reset_email(email, reset_link):
    """
        Sending email reset
    """
    try:
        send_email(email, "Password Reset", f"If you requested a password reset. \n\n"
                  f"Click this link to reset your password: {reset_link} \n\n If you didn't make this request, ignore this email.")
        logging.info("Password reset email sent to %s", email)
    except Exception as e:
        logging.error('Failed to send message %s', e)

def send_email(to, subject, body):
    """
        Sending mails logic
    """
    from_email = os.getenv('MAIL_USERNAME')
    password = os.getenv('MAIL_PASSWORD')
        
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to
    
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(from_email, password)
            server.send_message(msg)
        logging.info('Email sent successfully')
    except Exception as e:
        logging.error("Failed to send email %s", e)

@user_routes.route('/register', methods=['POST'])
def register_user():
    """
        Registering of users
    """

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'Error': "All fields are required"}), 400

    user_exists = User.query.filter(
        (User.username == username) | (User.email == email)).first()
    if user_exists:
        return jsonify({'Error': 'Username or Email already exists'}), 400

    hashed_password = generate_password_hash(password)
    try:
        new_user = User(username=username, email=email,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        # Send email verificaiton using firebase
        user = auth.create_user(email=email, password=password, email_verified=False)
        verification_link = auth.generate_email_verification_link(email)
        
        # Send the verification link to the user
        send_email_verification(email, verification_link)
        return jsonify({'message': 'User registered successfully. Please verify yoour email.'}), 201
    except Exception as e:
        logging.error('An Error occured due to: %s', e)
        return jsonify({'Error': 'An Error occured. Please try again'}), 500


@user_routes.route('/login', methods=['POST'])
def login_user():
    """
        Login User
    """

    data = request.get_json()
    user_input = data.get('user_input')
    password = data.get('password')

    if not user_input or not password:
        return jsonify({'Error': 'All fields are required'}), 400

    user_exists = User.query.filter((
        User.username == user_input) | (User.email == user_input)).first()
    if not user_exists or not check_password_hash(user_exists.password,
                                                  password):
        return jsonify({'Error': 'Invalid credentials'}), 400

    return jsonify({'message': 'Login successful'}), 200


@user_routes.route('/')
def home():
    """
        Home Page (for development/testing purposes)
    """
    return "Hello World!"


@user_routes.route('/request_reset', methods=['POST'])
def request_reset():
    """
        Request reset for password using
    """

    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'Error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'Error': 'User does not exists'}), 400

    reset_token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(minutes=15)
    }, SECRET_KEY, algorithm='HS256')
    
    try:
        reset_link = url_for("user_routes.password_reset", token=reset_token, _external=True)
        # logging.info('Reset link: %s', reset_link)
        send_reset_email(email, reset_link)
        return jsonify({'message': "If this email is registered, you will receive a reset link soon." }), 200
    except Exception as e:
        logging.error('Error sending password reset email: %s', e)
        return jsonify({"Error": "Failed to send password reset email. Please try again"}), 500


@user_routes.route('/password_reset/<token>', methods=['POST'])
def password_reset(token):
    """
        Password reset using token pass in logs
    """

    data = request.get_json()
    new_password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not new_password or not confirm_password:
        return jsonify({'Error': 'All fields are required'}), 400

    if new_password != confirm_password:
        return jsonify({'Error': 'Passwords do not match'}), 400

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload.get('user_id')

        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'Error': 'User not found'}), 404
        hashed_password = generate_password_hash(new_password)
        user.password =  hashed_password
        db.session.commit()
        return jsonify({'message': 'Password reset successful'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'Error': 'Token has expired'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'Error': 'Invalid token'}), 400
    except Exception as e:
        logging.error('An Error occured due to: %s', e)
        return jsonify({'Failed to reset password. Please try again'}), 500
