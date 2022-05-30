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

productapi = Blueprint(name="productapi", import_name=__name__)

#traitement erreur 
@productapi.errorhandler(400)
def create_failed(error):
  return make_response(jsonify({"error": "bad input"}), 400)
  
@productapi.errorhandler(500)
def internalServer(error):
  return make_response(jsonify({'error': 'Internal Server Error' }), 500)


@productapi.route('/products/add', methods=['POST'])
#@jwt_required()
def addProducts():
   
    if not request.json:
        abort(400)
    if 'code' in request.json and isinstance(request.json['code'], str) == False:
        abort(400)  
    if 'title' in request.json and isinstance(request.json['title'], str) == False:
        abort(400)
    if 'description' in request.json and isinstance(request.json['description'], str) == False:
        abort(400)
    if  'price' not in request.json or 'title' not in request.json or 'category' not in request.json: 
        abort(400)
   
    project = request.get_json()
    project['state'] = "waiting"
        
    try:
        pro = products.insert_one(project)
    except Exception:
        abort(500)
    proj = products.find_one({'_id': ObjectId(pro.inserted_id)})
    resp = jsonify(json.loads(json_util.dumps(proj)))
    resp.status_code= 200
    return resp
    

#get All products 
@productapi.route('/products/getAll/', methods=['GET'])
def allProducts():
    
    output = []
    for d in products.find().sort('created', -1):
        output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

#Search products by category 
@productapi.route('/projects/get/<category>', methods=['GET'])
def productsByCategory(category):
    
    output = []
    for d in products.find({'category': str(category), 'state': "available"}):
       output.append(json.loads(json_util.dumps(d)))
   
    resp = jsonify(output)
    resp.status_code=200
    return resp  

#Search products by Id 
@productapi.route('/products/get/<id>', methods=['GET'])
def productsByID(id):
   
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)
    product = products.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(product)))
    resp.status_code = 200
    return resp

#get All products with filter: tye, categories, price,  and rate 
# using post methdd
@productapi.route('/products/filter/', methods=['POST'])
def allPorojectsFilter():

    if not request.json:
        abort(400)

    data = request.json
    filter = {}
    orderby ={}
    if 'types' in data:
      filter['type'] = {"$in": data['type']}
    if 'categories' in data:
       filter['category'] = {"$in": data['categories']}
    if 'typeSort' in data and data['typeSort'] == "LowToHigh":
       orderby["price"] = 1
    if 'typeSort' in data and data['typeSort'] == "HighToLow":
      orderby["price"] = -1
    if 'typeSort' in data and data['typeSort']== "lastest":
        orderby["created"] = -1
    if 'typeSort' in data and data['typeSort']== "popularity":
         orderby["stars"] = -1

    filter['state'] = "available"
    
    res = products.find({ "$query": filter, "$orderby": orderby})
    output = []
    for d in res: 
        output.append(json.loads(json_util.dumps(d)))
    
    resp = jsonify(output)
    resp.status_code = 200
    return resp

#Search by name of the produc
@productapi.route('/products/searchByName/<name>', methods=['GET'])
def searchByName(name):
    
    output =[]
    for d in products.find({'name': {'$regex' : name, '$options' : 'i' }}):
        output.append(json.loads(json_util.dumps(d)))
      
    resp = jsonify(output)
    resp.status_code = 200
    return resp


# update  producct 
@productapi.route('/products/update/<id>', methods=['PUT'])
#@jwt_required()
def updateProduct(id):

    
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)
    
    if not request.json:
        abort(400)
  
    col = products.find_one({'_id': ObjectId(id)})
           
    if col ==None:
        resp = jsonify({"message": "product does not exist in database"})
        resp.status_code = 404
        return resp
    
    if 'code' in request.json and isinstance(request.json['code'], str) == False:
        abort(400)  
    if 'title' in request.json and isinstance(request.json['title'], str) == False:
        abort(400)
    if 'description' in request.json and isinstance(request.json['description'], str) == False:
        abort(400)
    if  'price' not in request.json or 'title' not in request.json or 'category' not in request.json or 'currency' not in request.json: 
        abort(400)
    
    prod = request.get_json()    
    
    try:
        res = customers.update_one({'_id': ObjectId(id)}, {'$set': prod})
    except Exception:
        abort(500)
    
    return jsonify(json.loads(json_util.dumps(customers.find_one({'_id': ObjectId(id)}))))


if __name__ == '__main__':
    app.run(debug=True)

