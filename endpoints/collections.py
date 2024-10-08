#from apicore import api, Http501Exception
from sqlite3 import Date
from flask import request, make_response, abort
from flask import Flask, Blueprint, jsonify
from flask_pymongo import PyMongo
import os
import time
from datetime import datetime
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from werkzeug.utils import secure_filename
import json
from flask.json import jsonify
from bson.objectid import ObjectId
from bson import objectid, json_util
from endpoints.utilsFunction import *
from . import *

collectionsapi = Blueprint(name="collectionsapi", import_name=__name__)

#traitement erreur 
@collectionsapi.errorhandler(400)
def create_failed(error):
  return make_response(jsonify({"error": "bad input"}), 400)
  
@collectionsapi.errorhandler(500)
def internalServer(error):
  return make_response(jsonify({'error': 'Internal Server Error' }), 500)


@collectionsapi.route('/admin/collections/add', methods=['POST'])
#@jwt_required()
def addCollection():

    
    if not request.json:
        abort(400)
   
    if 'title' in request.json and isinstance(request.json['title'], str) == False:
        abort(400)
   
    if  'products' not in request.json or "type" not in request.json: 
        abort(400)
   
    project = request.get_json()
    project['state'] = "disabled"
        
    try:
        pro = collections.insert_one(project)
    except Exception:
        abort(500)
    proj = collections.find_one({'_id': ObjectId(pro.inserted_id)})
    resp = jsonify(json.loads(json_util.dumps(proj)))
    resp.status_code= 200
    return resp
    

#get All collections 
@collectionsapi.route('/collections/getAll/', methods=['GET'])
def allCollections():
    
    output = []
    for d in collections.find().sort('created', -1):
        output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

#Search collection by Id 
@collectionsapi.route('/collections/get/<id>', methods=['GET'])
def collectionByID(id):
   
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)
    product = collections.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(product)))
    resp.status_code = 200
    return resp

# update state of the collecion 
@collectionsapi.route('/collections/update/<state>/<id>/', methods=['PUT'])
#@jwt_required()
def updateCollectionState(id, state):

       
    if ObjectId.is_valid(id) == False:
        return   make_response(jsonify({"error": "invalid ID"}), 400)
    
    if not request.json:
        abort(400)
    col = collections.find_one({'_id': ObjectId(id)})
           
    if col ==None:
        resp = jsonify({"message": "collection does not exist in database"})
        resp.status_code = 404
        return resp 
    
    try:
        res = collections.update_one({'_id': ObjectId(id)}, {
                               '$set': {"state": state}})
    except Exception:
        abort(500)
   
    user = collections.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(user)))
    resp.status_code = 200
    
    return resp

# update  collecion 
@collectionsapi.route('/collections/update/<id>/', methods=['PUT'])
#@jwt_required()
def updateCollection(id):
    
    if ObjectId.is_valid(id) == False:
        return   make_response(jsonify({"error": "invalid ID"}), 400)
    
    if not request.json:
        abort(400)
    col = collections.find_one({'_id': ObjectId(id)})
           
    if col ==None:
        resp = jsonify({"message": "collection does not exist in database"})
        resp.status_code = 404
        return resp 
    coll = request.get_json()
    try:
        res = collections.update_one({'_id': ObjectId(id)}, {'$set': coll})
    except Exception:
        abort(500)
   
    user = collections.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(user)))
    resp.status_code = 200
    
    return resp
#Delete a collection  by ID
@collectionsapi.route('/collections/delete/<id>/', methods=['DELETE'])
#@jwt_required()
def deleteCollection(id):

   
    try:
        collections.delete_one({'_id': ObjectId(id)})
    except Exception:
        abort(500)

    return success()

# Left and right on the down of the home page#

@collectionsapi.route('/collectionsCat/add', methods=['POST'])
#@jwt_required()
def addCollectioncat():
    
    if not request.json:
        abort(400)
   
    if 'image' in request.json and isinstance(request.json['image'], str) == False:
        abort(400)
   
    if  'category' not in request.json or "type" not in request.json: 
        abort(400)
   
    data = request.get_json()
    data['state'] = "disabled"
        
    try:
        pro = collectionCat.insert_one(data)
    except Exception:
        abort(500)
    proj = collectionCat.find_one({'_id': ObjectId(pro.inserted_id)})
    resp = jsonify(json.loads(json_util.dumps(proj)))
    resp.status_code= 200
    return resp

# update  collecion category 
@collectionsapi.route('/collectionsCat/update/<id>/', methods=['PUT'])
#@jwt_required()
def updateCollectionCat(id):
    
    if ObjectId.is_valid(id) == False:
        return   make_response(jsonify({"error": "invalid ID"}), 400)
    
    if not request.json:
        abort(400)
    col = collectionCat.find_one({'_id': ObjectId(id)})
           
    if col ==None:
        resp = jsonify({"message": "collection does not exist in database"})
        resp.status_code = 404
        return resp 
    coll = request.get_json()
    try:
        res = collectionCat.update_one({'_id': ObjectId(id)}, {'$set': coll})
    except Exception:
        abort(500)
   
    colcat = collectionCat.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(colcat)))
    resp.status_code = 200
    
    return resp

#Delete a collection  by ID
@collectionsapi.route('/collectionsCat/delete/<id>/', methods=['DELETE'])
#@jwt_required()
def deleteCollectionCat(id):
   
    try:
        collectionCat.delete_one({'_id': ObjectId(id)})
    except Exception:
        abort(500)

    return success()


#get All collectionCat 
@collectionsapi.route('/collectionsCat/getAll/', methods=['GET'])
def allCollectionCat():
    
    output = []
    for d in collectionCat.find().sort('created', -1):
        output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

#Search collection by Id 
@collectionsapi.route('/collectionsCat/get/<id>', methods=['GET'])
def collectionCatByID(id):
   
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)
    c = collectionCat.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(c)))
    resp.status_code = 200
    return resp

# update state of the collecion 
@collectionsapi.route('/collectionsCat/update/<state>/<id>/', methods=['PUT'])
#@jwt_required()
def updateCollectioCatState(id, state):

    if ObjectId.is_valid(id) == False:
        return   make_response(jsonify({"error": "invalid ID"}), 400)
    
    if not request.json:
        abort(400)
    col = collectionCat.find_one({'_id': ObjectId(id)})
           
    if col ==None:
        resp = jsonify({"message": "collection does not exist in database"})
        resp.status_code = 404
        return resp 
    
    try:
        res = collectionCat.update_one({'_id': ObjectId(id)}, {
                               '$set': {"state": state}})
    except Exception:
        abort(500)
   
    cat = collectionCat.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(cat)))
    resp.status_code = 200
    
    return resp

if __name__ == '__main__':
    app.run(debug=True)

