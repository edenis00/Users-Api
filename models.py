"""
    Importing packages
"""
from extension import db


class User(db.Model):
    """
        Creating the user table
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), unique=True, nullable=False)

    def __repr__(self):
        return f"<User {self.username} >"
