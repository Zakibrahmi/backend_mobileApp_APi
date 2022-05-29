
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
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
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

#get ALl categories
@categoryapi.route('/categories/', methods=['GET'])

def allCategories():  
   output = []
   for d in categories.find():
        output.append(json.loads(json_util.dumps(d)))         
       
   resp = jsonify(output)
   resp.status_code=200 
   return resp

#add category
@categoryapi.route('/categories/add/', methods=['POST'])
@jwt_required()
def addCategories():    
   
    if not request.json:
        abort(400)
    if 'title' not in request.json:
        abort(400) 
        
    category = request.get_json()
    try:
        res = categories.insert_one(category)
    except Exception:
        return internalServer()

    u = categories.find_one({'_id': ObjectId(res.inserted_id)})
    resp = jsonify(json.loads(json_util.dumps(u)))
    resp.status_code = 200
    return resp
  
# get category by ID
@categoryapi.route('/categories/get/<id>', methods=['GET'])

def packageByID(id): 
    
    package = categories.find_one({'_id': ObjectId(id)})
    if package == None:
      return not_found()
    resp = jsonify(json.loads(json_util.dumps(package)))
    resp.status_code=200
    return resp

#update category by ID
@categoryapi.route('/categories/update/<id>/', methods=['PUT'])
@jwt_required()
def updateCategory(id):
    
    if ObjectId.is_valid(id) == False:
        return   make_response(jsonify({"error": "invalid ID"}), 400)
    
    if not request.json:
        abort(400)

    if 'title' not in request.json:
      abort(400)
    
    cat = request.get_json()
    try:
        res = categories.update_one({'_id': ObjectId(id)}, {'$set': cat})
    except Exception:
        abort(500)
    
    return jsonify(json.loads(json_util.dumps(categories.find_one({'_id': ObjectId(id)}))))

#Delete a categroeis  by ID
@categoryapi.route('/categories/delete/<id>/', methods=['DELETE'])
@jwt_required()
def deleteCat(id):
   
    if ObjectId.is_valid(id) == False:
        return   make_response(jsonify({"error": "invalid ID"}), 400)
    
    try:
        categories.delete_one({'_id': ObjectId(id)})
    except Exception:
        abort(500)

    return success()
               
if __name__ == '__main__':
    app.run(debug=True)


