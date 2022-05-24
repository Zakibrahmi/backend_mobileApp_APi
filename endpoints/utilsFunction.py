
from flask import jsonify

from flask_pymongo import PyMongo
import os
from flask import Flask, request, make_response
import re
import json
import jwt
from flask.json import jsonify
from bson.objectid import ObjectId

"""from requests.exceptions import ConnectionError, HTTPError
from exponent_server_sdk import (
    DeviceNotRegisteredError,
    PushClient,
    PushMessage,
    PushServerError,
)"""

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'waedLineDB'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/waedLineDB'
app.secret_key = "004f2af45d3a4e161a7dd2d17fdae47f"

mongo = PyMongo(app)
customers=mongo.db.customers   
admins=mongo.db.admins   

def internalServer(error):
    return make_response(jsonify({'error': 'Internal Server Error'}), 500)
    
def id_inalid(id):
    message = {
               'status': 403,
               'message': 'Id invalid: ' + id,
             }
    resp = jsonify(message)
    return resp
    
def success():
    message = {
               'status': 200,
               'message': "success"
             }        
    resp = jsonify(message)
    return resp

#JWT
def token_required(f):
   
   def decorator(*args, **kwargs):
       token = None
       if 'x-api-key' in request.headers:
           token = request.headers['x-api-key']
 
       if not token:
           return jsonify({'message': 'a valid token is missing'})
       try:
          data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
          current_user = customers.find_one({'_id': ObjectId(data['_id'])})
       except:
          return jsonify({'message': 'token is invalid'})
 
       return f(current_user, *args, **kwargs)
   return decorator

# function for verifying the access token
def token_required_admin(data):
      token = None
        # jwt is passed in the request header
      if 'Authorization' in data:
            token = data['Authorization']
        # return 401 if token is not passed
      else: 
        return "Token is missing !!"
      #split tokne to: Bearer firebaseId phone/Email
      g = re.match("^Bearer\s+(.*)", token)

      if not g:
        return "invalid Token" 
      token =  g.group(1)
      w = token.split()

      try:
           user = admins.find_one({'oidFirebase': w[0]})
      except:
          return "internal server problem !!" 
      if user == None:
        return "Access Denied" 
      return "authorized"