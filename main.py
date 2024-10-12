"""
    Importing Depencies
"""
import os
import uvicorn
from migrate import fastapi_app

if __name__ == '__main__':
    uvicorn.run(fastapi_app, host="0.0.0.0", port=int(os.getenv('PORT', 8000)))
