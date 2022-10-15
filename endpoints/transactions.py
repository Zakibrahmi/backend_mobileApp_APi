from formatter import NullFormatter
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

transactionsapi = Blueprint(name="transactionsapi", import_name=__name__)

# traitement erreur
@transactionsapi.errorhandler(400)
def create_failed(error):
    return make_response(jsonify({"error": "bad input"}), 400)

@transactionsapi.errorhandler(500)
def internalServer(error):
    return make_response(jsonify({'error': 'Internal Server Error'}), 500)


@transactionsapi.errorhandler(403)
def user_notfound(id):
    message = {
        'status': 403,
        'message': 'User not Found: ' + str(id),
    }
    resp = jsonify(message)
    return resp

@transactionsapi.errorhandler(404)
def not_found(error=None):
    message = {
        'status': 404,
        'message': 'Not Found: ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp

#Add  transaction
@transactionsapi.route('/transaction/add', methods=['POST'])
#@jwt_required()
def addTransaction():
   
    if not request.json:
        abort(400)
    if  "transaction" not in request.json:
        abort(400)
           
    orderID = request.args.get("orderId")
    if orderID == None:
        message = {
            'status': 404,
            'message': 'No prameters',
        }
        resp = jsonify(message)
        resp.status_code = 404
        return resp
    trans = request.get_json()   
    trans['createdAt'] = time.strftime('%d/%m/%Y %H', time.localtime())
    trans['order'] = orderID
    try:
        pro = transactions.insert_one(trans)
    except Exception:
        abort(500)
    
    resp = jsonify()
    resp.status_code= 200
    return resp

# get transaction by order ID
@transactionsapi.route('/transactions/order/<id>/', methods=['GET'])
#@jwt_required()
def getTransactionByOrder(id):
  
   # iduser = get_jwt_identity()
    trans = transactions.find_one({'order': id})    
    resp = jsonify(json.loads(json_util.dumps(trans)))
    resp.status_code = 200
    return resp

# get All transactions  by page
@transactionsapi.route('/transactions/getALl/', methods=['GET'])
#@jwt_required()
def getAllTransactions():
  
    page = request.args.get("page")
   
    limitcollection = request.args.get('limit')
    startIndex = (int(page) - 1) * int(limitcollection)
        
    order = ['createdAt', -1]    

    # filter courses get document counts
    output = []
    results = transactions.find().sort(order[0], order[1]).limit(int(limitcollection)).skip(startIndex)
   
    for d in results: 
        output.append(json.loads(json_util.dumps(d)))
   
    resp = jsonify(output)
    #resp = jsonify(json.loads(json_util.dumps(filter)))
    resp.status_code = 200
    return resp

if __name__ == '__main__':
    app.run(debug=True)

