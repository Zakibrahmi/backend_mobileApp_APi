#!/usr/bin/env python
from flask import Flask, jsonify
import sys

from datetime import timedelta
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

from endpoints.customrs import  customersapi
from endpoints.products import  productapi
from endpoints.settings import  settingsapi


app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "004f2af45d3a4e1578b1a7dd2d17fdae47f"  # Change this!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=3)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
#app.config['JWT_ALGORITHM'] = 'HS512'

jwt = JWTManager(app)

# register blueprints. ensure that all paths are versioned!
app.register_blueprint(productapi, url_prefix="/")
app.register_blueprint(customersapi, url_prefix="/")
app.register_blueprint(settingsapi, url_prefix="/")
