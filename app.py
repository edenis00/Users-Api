"""
    Importing Packages
"""
import os
from flask import Flask
from flask_migrate import Migrate
from flask_cors import CORS
from extension import db
from routes.user_routes import user_routes
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
db.init_app(app)
migrate = Migrate(app, db)

app.register_blueprint(user_routes, url_prefix='/users')

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_ENV') == 'development')
