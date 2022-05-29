
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
brandsapi = Blueprint(name="brandsapi", import_name=__name__)


#traitement erreur 
@brandsapi.errorhandler(400)
def create_failed(error):
  return make_response(jsonify({"error": "bad input"}), 400)
  
@brandsapi.errorhandler(500)
def internalServer(error):
  return make_response(jsonify({'error': 'Internal Server Error' }), 500)

@brandsapi.errorhandler(403)
def user_notfound(id):
    message = {
               'status': 403,
               'message': 'User not Found: ' + id,
             }
    resp = jsonify(message)
    return resp

@brandsapi.errorhandler(403)
def not_found(error=None):
    message = {
               'status': 404,
               'message': 'Not Found: ' + request.url,
             }
    resp = jsonify(message)
    resp.status_code = 404
    return resp

#get ALl brands
@brandsapi.route('/brands/', methods=['GET'])
def allBrands():  
   output = []
   for d in brands.find():
        output.append(json.loads(json_util.dumps(d)))         
       
   resp = jsonify(output)
   resp.status_code=200 
   return resp

#add category
@brandsapi.route('/brands/add/', methods=['POST'])
def addBrand():  
   
   
  if not request.json:
        abort(400)
  if 'title' not in request.json:
        abort(400) 
        
  brd = request.get_json()
  try:
        res = brands.insert_one(brd)
  except Exception:
        return internalServer()

  u = brands.find_one({'_id': ObjectId(res.inserted_id)})
  resp = jsonify(json.loads(json_util.dumps(u)))
  resp.status_code = 200
  
  return resp
  
# get brand by ID
@brandsapi.route('/brands/get/<id>', methods=['GET'])
def  brandByID(id): 
    
    brd = brands.find_one({'_id': ObjectId(id)})
    if brd == None:
      return not_found()
    resp = jsonify(json.loads(json_util.dumps(brd)))
    resp.status_code=200
    return resp

#update brand by ID
@brandsapi.route('/brands/update/<id>/', methods=['PUT'])
def updateBrand(id):

    decison = token_required_admin(request.headers)
    if decison != "authorized":
        return jsonify({'message': decison}), 401
    
    if ObjectId.is_valid(id) == False:
        return   make_response(jsonify({"error": "invalid ID"}), 400)
    
    if not request.json:
        abort(400)

    if 'title' not in request.json:
      abort(400)
    
    cat = request.get_json()
    try:
        res = brands.update_one({'_id': ObjectId(id)}, {'$set': cat})
    except Exception:
        abort(500)
    
    return jsonify(json.loads(json_util.dumps(brands.find_one({'_id': ObjectId(id)}))))

#Delete a brand  by ID
@brandsapi.route('/brands/delete/<id>/', methods=['DELETE'])
def deleteBrand(id):

    decison = token_required_admin(request.headers)
    if decison != "authorized":
        return jsonify({'message': decison}), 401

    try:
        brands.delete_one({'_id': ObjectId(id)})
    except Exception:
        abort(500)

    return success()

                
if __name__ == '__main__':
    app.run(debug=True)


