"""
    Importing Dependencies
"""

from fastapi import FastAPI
from flask_migrate import upgrade
from app import app as flask_app

fastapi_app = FastAPI()


@fastapi_app.get("/migrate")
async def migrate():
    """
        For Migration
    """
    with flask_app.app_context():
        upgrade()
    return {"status": "Migrations applied successfully!"}
