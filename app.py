"""
    Importing Packages
"""
import os
import logging
import firebase_admin
from firebase_admin import credentials
from flask import Flask
from flask_migrate import Migrate
from flask_mail import Mail
from flask_cors import CORS
from dotenv import load_dotenv
from routes.user_routes import user_routes
from extension import db

load_dotenv()

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


if not firebase_admin._apps:
    cred = credentials.Certificate('./firebase_credentials.json')
    firebase_admin.initialize_app(cred)

mail = Mail(app)
CORS(app)
db.init_app(app)
migrate = Migrate(app, db)


if __name__ == '__main__':
    from routes.user_routes import user_routes
    app.register_blueprint(user_routes, url_prefix='/users')
    app.run(debug=os.getenv('FLASK_ENV') == 'development')
