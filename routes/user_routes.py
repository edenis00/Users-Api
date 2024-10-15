"""
 Importing Packages
"""
import logging
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User

user_routes = Blueprint('user_routes', __name__)


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
        logging.error(f"An Error occured due to {e}")
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
