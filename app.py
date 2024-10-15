"""
    Importing Packages
"""
import os
import logging
from flask import Flask
from flask_migrate import Migrate
from flask_cors import CORS
from dotenv import load_dotenv
from routes.user_routes import user_routes
from extension import db

load_dotenv()

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
db.init_app(app)
migrate = Migrate(app, db)

app.register_blueprint(user_routes, url_prefix='/users')

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_ENV') == 'development')
