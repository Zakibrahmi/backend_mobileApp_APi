from logging.config import IDENTIFIER
from math import trunc
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

ordersapi = Blueprint(name="ordersapi", import_name=__name__)

# traitement erreur
@ordersapi.errorhandler(400)
def create_failed(error):
    return make_response(jsonify({"error": "bad input"}), 400)

@ordersapi.errorhandler(500)
def internalServer(error):
    return make_response(jsonify({'error': 'Internal Server Error'}), 500)


@ordersapi.errorhandler(403)
def user_notfound(id):
    message = {
        'status': 403,
        'message': 'User not Found: ' + str(id),
    }
    resp = jsonify(message)
    return resp


@ordersapi.errorhandler(404)
def not_found(error=None):
    message = {
        'status': 404,
        'message': 'Not Found: ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp

#Add order
@ordersapi.route('/order/add', methods=['POST'])
#@jwt_required()
def addOrderClient():
   
    if not request.json:
        abort(400)
    if 'customer' not in request.json or "items" not in request.json or "shippingId" not in request.json:
        abort(400)
    if ObjectId.is_valid(request.json['customer']) == False:
        return id_inalid(request.json['customer'])        
   
    order = request.get_json()
    order['date'] = time.strftime('%d/%m/%Y %H', time.localtime())
   
    try:
        pro = orders.insert_one(order)
    except Exception:
        abort(500)
    ord = orders.find_one({'_id': ObjectId(pro.inserted_id)})
    resp = jsonify(json.loads(json_util.dumps(ord)))
    resp.status_code= 200
    return resp

# get orders of the customer id
@ordersapi.route('/customers/orders/customer/<id>/', methods=['GET'])
#@jwt_required()
def getUserOrders(id):
  
   # iduser = get_jwt_identity()
    ord = orders.find({'customer': id})    
    output = []
    for d in ord:
        output.append(json.loads(json_util.dumps(d)))
    resp = jsonify(output)
    resp.status_code = 200
    return resp

# get orders by id
@ordersapi.route('/customers/orders/<id>/', methods=['GET'])
#@jwt_required()
def getOrderById(id):
  
   # iduser = get_jwt_identity()
    ord = orders.find_one({'_id': ObjectId(id)})    
    resp = jsonify(json.loads(json_util.dumps(ord)))
    
    resp.status_code = 200
    return resp

# get All order of all users by page
@ordersapi.route('/admin/customers/orders/', methods=['GET'])
#@jwt_required()
def getAllOrders():
  
    page = request.args.get("page")
   
    limitcollection = request.args.get('limit')
    startIndex = (int(page) - 1) * int(limitcollection)
        
    order = ['createdAt', -1]    

    # filter orders; get document counts
    output = []
    results = orders.find().sort(order[0], order[1]).limit(int(limitcollection)).skip(startIndex)
   
    for d in results: 
        output.append(json.loads(json_util.dumps(d)))
   
    resp = jsonify(output)
    #resp = jsonify(json.loads(json_util.dumps(filter)))
    resp.status_code = 200
    return resp

#Updaye order state
@ordersapi.route('/admin/orders/update/state/<id>/<state>/', methods=['PUT'])
def updatOrderState(id, state):
    
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)        
    order = admins.find_one({'_id': ObjectId(id)})

    # Email not exist in dataBase
    if order == None:
        resp = jsonify({"message": "This user not exist in database"})
        resp.status_code = 404
        return resp
    try:
        res = orders.update_one({'_id': ObjectId(id)}, {'$set': {"state": state}})
    except Exception:
        abort(500)

    if res.modified_count == 0:
        return user_notfound(id)
    
    return jsonify(json.loads(json_util.dumps(orders.find_one({'_id': ObjectId(id)}))))

if __name__ == '__main__':
    app.run(debug=True)

