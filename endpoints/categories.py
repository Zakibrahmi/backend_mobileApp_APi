
from flask import request, make_response, abort
from flask import Flask, Blueprint
from flask import jsonify
from flask_pymongo import PyMongo
import os
from werkzeug.utils import secure_filename
import json
from flask.json import jsonify
from bson.objectid import ObjectId
from bson import objectid, json_util
from endpoints.utilsFunction import *
import time
import operator
from . import *

app = Flask(__name__)
categoryapi = Blueprint(name="categoryapi", import_name=__name__)


#traitement erreur 
@categoryapi.errorhandler(400)
def create_failed(error):
  return make_response(jsonify({"error": "bad input"}), 400)
  
@categoryapi.errorhandler(500)
def internalServer(error):
  return make_response(jsonify({'error': 'Internal Server Error' }), 500)

@categoryapi.errorhandler(403)
def user_notfound(id):
    message = {
               'status': 403,
               'message': 'User not Found: ' + id,
             }
    resp = jsonify(message)
    return resp

@categoryapi.errorhandler(403)
def not_found(error=None):
    message = {
               'status': 404,
               'message': 'Not Found: ' + request.url,
             }
    resp = jsonify(message)
    resp.status_code = 404
    return resp

@categoryapi.route('/categories/', methods=['GET'])
def allCategories():  
   output = []
   for d in categories.find():
        output.append(json.loads(json_util.dumps(d)))         
       
   resp = jsonify(output)
   resp.status_code=200 
   return resp

# get package by ID
@categoryapi.route('/categories/get/<id>', methods=['GET'])
def packageByID(id): 
    
    package = categories.find_one({'_id': ObjectId(id)})
    if package == None:
      return not_found()
    resp = jsonify(json.loads(json_util.dumps(package)))
    resp.status_code=200
    return resp
                     
if __name__ == '__main__':
    app.run(debug=True)


