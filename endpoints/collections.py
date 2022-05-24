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
def addProducts():

    if not request.json:
        abort(400)
   
    if 'title' in request.json and isinstance(request.json['title'], str) == False:
        abort(400)
    if 'description' in request.json and isinstance(request.json['description'], str) == False:
        abort(400)
    if  'products' not in request.json or "order" not in request.json: 
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
def allProducts():
    
    output = []
    for d in collections.find().sort('created', -1):
        output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

#Search collection by Id 
@collectionsapi.route('/collections/get/<id>', methods=['GET'])
def productsByID(id):
   
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)
    product = collections.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(product)))
    resp.status_code = 200
    return resp


if __name__ == '__main__':
    app.run(debug=True)

