from hashlib import new
from logging.config import IDENTIFIER
from math import trunc
from datetime import datetime


from flask import request, make_response, abort, session

from flask import Flask, Blueprint, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from flask_pymongo import PyMongo
import uuid
from werkzeug.utils import secure_filename
import json
from flask.json import jsonify
from bson.objectid import ObjectId
from bson import objectid, json_util
import time
from datetime import timedelta
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from endpoints.utilsFunction import *
from . import *

retunrapi = Blueprint(name="retunrapi", import_name=__name__)

# traitement erreur
@retunrapi.errorhandler(400)
def create_failed(error):
    return make_response(jsonify({"error": "bad input"}), 400)

@retunrapi.errorhandler(500)
def internalServer(error):
    return make_response(jsonify({'error': 'Internal Server Error'}), 500)


@retunrapi.errorhandler(403)
def user_notfound(id):
    message = {
        'status': 403,
        'message': 'User not Found: ' + str(id),
    }
    resp = jsonify(message)
    return resp


@retunrapi.errorhandler(404)
def not_found(error=None):
    message = {
        'status': 404,
        'message': 'Not Found: ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp

#Add returns
@retunrapi.route('/returns/add', methods=['POST'])
#@jwt_required()
def addReturnsClient():
   
    if not request.json:
        abort(400)
    if 'customer' not in request.json or "items" not in request.json or "orderId" not in request.json:
        abort(400)
    if ObjectId.is_valid(request.json['customer']) == False:
        return id_inalid(request.json['customer'])        
   
    returned = request.get_json()
    states =[]
    states.append({'date' : time.strftime('%d/%m/%Y %H', time.localtime()),
                   "state" : "Return requested"}    
                )
    returned["states"] = states
    try:
        pro = returns.insert_one(returned)
    except Exception:
        abort(500)
      
    ord = returns.find_one({'_id': ObjectId(pro.inserted_id)})
    resp = jsonify(json.loads(json_util.dumps(ord)))
    resp.status_code= 200
    return resp

# get returns of the customer id
@retunrapi.route('/customers/returns/customer/<id>/', methods=['GET'])
#@jwt_required()
def getUserReturnes(id):
  
   # iduser = get_jwt_identity()
    ord = returns.find({'customer': id})    
    output = []
    for d in ord:
        output.append(json.loads(json_util.dumps(d)))
    resp = jsonify(output)
    resp.status_code = 200
    return resp

# get returns by id
@retunrapi.route('/customers/returns/<id>/', methods=['GET'])
#@jwt_required()
def getReturnsById(id):
  
   # iduser = get_jwt_identity()
    ord = returns.find_one({'_id': ObjectId(id)})    
    resp = jsonify(json.loads(json_util.dumps(ord)))
    
    resp.status_code = 200
    return resp

# get All returns of all users by page
@retunrapi.route('/admin/customers/returns/', methods=['GET'])
#@jwt_required()
def getAllReturns():
  
    page = request.args.get("page")
   
    limitcollection = request.args.get('limit')
    startIndex = (int(page) - 1) * int(limitcollection)
        
    order = ['createdAt', -1]    

    # filter orders; get document counts
    output = []
    results = returns.find().sort(order[0], order[1]).limit(int(limitcollection)).skip(startIndex)
   
    for d in results: 
        output.append(json.loads(json_util.dumps(d)))
   
    resp = jsonify(output)
    #resp = jsonify(json.loads(json_util.dumps(filter)))
    resp.status_code = 200
    return resp

# add return state. The new state will be on the request
@retunrapi.route('/admin/returns/add/newstate/<id>/', methods=['PUT'])
def addReturnState(id):
    
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)        
    ret = returns.find_one({'_id': ObjectId(id)})
  
    # return not exist in dataBase
    if ret == None:
        resp = jsonify({"message": "This return does't exist in database"})
        resp.status_code = 404
        return resp

    newState = request.get_json()["newState"]
    state= {'date' : time.strftime('%d/%m/%Y %H', time.localtime()),
            "state" : newState}    
    try:
        returns.update_one({'_id': ObjectId(id)}, {
                         '$push': {"states": state}})
    except Exception:
        abort(500)
    return jsonify(json.loads(json_util.dumps(returns.find_one({'_id': ObjectId(id)}))))

# update an existing  return state. Old an new state on request
@retunrapi.route('/admin/returns/update/state/<id>/', methods=['PUT'])
def updateReturnState(id):
    
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)        
    ret = returns.find_one({'_id': ObjectId(id)})
  
    # return not exist in dataBase
    if ret == None:
        resp = jsonify({"message": "This return does't exist in database"})
        resp.status_code = 404
        return resp

    oldState = request.get_json()['oldState']
    newState = request.get_json()['newState']
        
    try:
        returns.update_one({'_id': ObjectId(id), "states.state": oldState}, {"$set": {"states.$.state": newState}})
    except Exception:
        abort(500)
    return jsonify(json.loads(json_util.dumps(returns.find_one({'_id': ObjectId(id)}))))
 
# get Returned orders of the customer id
@retunrapi.route('/customers/returnedOrders/customer/<id>/', methods=['GET'])
#@jwt_required()
def getUserReturnedOrders(id):
  
   # iduser = get_jwt_identity()
    daysr= settings.find_one({}, {"daysToReturn": 1})
    previous_day = datetime.now() - timedelta(days=daysr['daysToReturn'])
    
    ord = orders.find({'customer': id, "state": "Delivered"})    
    output = []
    for d in ord:
        if (datetime.strptime(d["dateState"],"%d/%m/%Y %H") >  previous_day) :
           output.append(json.loads(json_util.dumps(d)))
    resp = jsonify(output)
    resp.status_code = 200
    return resp

if __name__ == '__main__':
    app.run(debug=True)

