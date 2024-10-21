"""
 Importing Packages
"""
import os
import logging
import datetime
import requests
import jwt
from flask import Blueprint, request, jsonify, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from models import db, User

load_dotenv()
MAILGUN_API_KEY = os.getenv('MAILGUN_API_KEY')
MAILGUN_DOMAIN = os.getenv('MAILGUN_DOMAIN')
MAILGUN_SENDER_EMAIL = os.getenv('MAILGUN_SENDER_EMAIL, noreply@example.com')
SECRET_KEY = os.getenv('SECRET_KEY')
user_routes = Blueprint('user_routes', __name__)


def send_reset_email(email, reset_link):
    """
        Sending email reset
    """
    return requests.post(
        f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
            auth=("api", MAILGUN_API_KEY),
            data={"from": f"Excited User <{MAILGUN_SENDER_EMAIL}>",
              "to": [email, f"YOU@{MAILGUN_DOMAIN}"],
              "subject": "Password Reset Request",
              "text": f"To reset your password, Click the following link: {reset_link}\n\n If you didnt request this, please ignore this email"},
        timeout=3
    )


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
        return jsonify({'message': 'User registered successfully'}), 201
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
        Request reset for password using (mailgun)
    """

    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'Error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'Error': 'User does not exists'}), 400

    reset_token = jwt.encode({
        "user_id": user.id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm="HS256")

    reset_url = url_for("user_routes.password_reset", token=reset_token, _external = True)
    response = send_reset_email(email, reset_url)
    logging.info("Mailgun response %s", response.text)
    # logging.info("Reset url sent: %s", reset_url)
    # if response.status_code == 200:
    logging.info("password reset link %s", reset_url)
    return jsonify({'message': f'Click this link to reset Password {reset_url}'}), 200
    # return jsonify({'message': f'If this email is registered, you will receive a reset link soon. Password link {reset_url}'}), 200
    # return jsonify({'Error': 'Failed to send request to email'}), 500


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
