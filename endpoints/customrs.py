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
from endpoints.utilsFunction import *
import time
from datetime import timedelta
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from endpoints.utilsFunction import *
from . import *

customersapi = Blueprint(name="customersapi", import_name=__name__)

# traitement erreur
@customersapi.errorhandler(400)
def create_failed(error):
    return make_response(jsonify({"error": "bad input"}), 400)

@customersapi.errorhandler(500)
def internalServer(error):
    return make_response(jsonify({'error': 'Internal Server Error'}), 500)


@customersapi.errorhandler(403)
def user_notfound(id):
    message = {
        'status': 403,
        'message': 'User not Found: ' + str(id),
    }
    resp = jsonify(message)
    return resp


@customersapi.errorhandler(404)
def not_found(error=None):
    message = {
        'status': 404,
        'message': 'Not Found: ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp


@customersapi.route('/customers/register', methods=['POST'])
def createCustomer():

    if not request.json:
        abort(400)
    if 'name' not in request.json or 'password' not in request.json or 'email' not in request.json:
        abort(400) 
    if isinstance(request.json['name'], str) == False:
        abort(400)
    if isinstance(request.json['password'], str) == False:
        abort(400)
    if 'city' in request.json and isinstance(request.json['city'], str) == False:
        abort(400)
    if 'counrty' in request.json and isinstance(request.json['counrty'], str) == False:
        abort(400)
    if isinstance(request.json['email'], str) == False:
        abort(400)
    if 'mobile' in request.json and isinstance(request.json['mobile'], str) == False:
        abort(400)

    customer = request.get_json()
    user = customers.find_one({'email': customer['email']})
    if user:
        resp = jsonify({"message": "An account already registered by this Email"})
        resp.status_code = 404
        return resp
    
    customer['created'] = time.strftime('%d/%m/%y', time.localtime())
    customer['password'] = generate_password_hash(customer['password'])
    try:
        res = customers.insert_one(customer)
    except Exception:
        return internalServer()

    user = customers.find_one({'_id': ObjectId(res.inserted_id)}, {'password': 0} )
    resp = jsonify(json.loads(json_util.dumps(u)))
    
    access_token = create_access_token(identity= str(user['_id']), fresh=True)
    refresh_token = create_refresh_token(identity= str(user['_id']))

    user['token'] = access_token
    user['refresh'] = refresh_token
    return jsonify({'ok': True, 'data': json.loads(json_util.dumps(user))}), 200

# update  customer account
@customersapi.route('/customers', methods=['PUT'])
#@jwt_required(refresh=True)
def updateCustomer():

    if not request.json:
        abort(400)
  
    if 'password' not in request.json  and 'email' not in request.json:
        abort(400) 
    if 'name' in request.json and isinstance(request.json['name'], str) == False:
        abort(400)
    if 'city' in request.json and isinstance(request.json['city'], str) == False:
        abort(400)
    if 'counrty' in request.json and isinstance(request.json['counrty'], str) == False:
        abort(400)
    if isinstance(request.json['email'], str) == False:
        abort(400)
    if 'mobile' in request.json and isinstance(request.json['mobile'], str) == False:
        abort(400)
    
    customer = request.get_json()
    customerId = get_jwt_identity()
    customer['password'] = generate_password_hash(customer['password'])
    
    try:
        res = customers.update_one({'_id': ObjectId(customerId)}, {'$set': customer})
    except Exception:
        abort(500)
    
    return jsonify(json.loads(json_util.dumps(customers.find_one({'_id': ObjectId(customerId)}))))


# get customer by ID
@customersapi.route('/customers/get/<iduser>', methods=['GET'])
def getUserByID(iduser):

    cost = customers.find_one({'_id': ObjectId(iduser)})
    resp = jsonify(json.loads(json_util.dumps(cost)))
    resp.status_code = 200
    return resp


# update shipping adress
@customersapi.route('/users/update/shippingAdress', methods=['PUT'])
@jwt_required()
def updateAdress():

    if not request.json:
        abort(400)

    idCutomer = get_jwt_identity()
    try:
        res = customers.update_one({'_id': ObjectId(idCutomer)}, {'$set': {"shippingAdress": request.get_json()}})
    except Exception:
        abort(500)

    if res.modified_count == 0:
        return user_notfound(idCutomer)
    return success()

# add the  favoris product  "idfavoris" to the favorites list of the custorm  idcustomer
@customersapi.route('/customers/favoris/<idfavoris>', methods=['PUT'])
@jwt_required()
def customerAddFavoris(idfavoris):

    idcustomer = get_jwt_identity()
    if ObjectId.is_valid(idfavoris) == False:
        return id_inalid(idfavoris)

    user = customers.find_one({'_id': ObjectId(idcustomer)})
    product = products.find_one({'_id': ObjectId(idfavoris)})
    # user of provier not exist in dataBase
    if user == None or product == None:
        resp = jsonify({"message": "customer or product not exist"})
        resp.status_code = 404
        return resp
    # Exist: update collection user
    try:
        customers.update_one({'_id': ObjectId(idcustomer)}, {'$addToSet': {"favoris": ObjectId(idfavoris)}})
    except Exception:
        return jsonify({"message": "update failed "})
    return success()

# get All user favorites
@customersapi.route('/customers/favoris', methods=['GET'])
@jwt_required()
def getFavoris():

    iduser = get_jwt_identity()
    favoris = customers.find_one({'_id': ObjectId(iduser)}, {"favoris": 1, '_id':0})
    # user of provier not exist in dataBase
    if favoris == None:
        resp = jsonify({"message": "user not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: get notifications
    output = []
    for f in favoris['favoris']:
       output.append(json.loads(json_util.dumps(products.find_one({'_id': ObjectId(f)}))))
       #output.append(json.loads(json_util.dumps(f)))
    
    resp = jsonify(output)
    resp.status_code = 200
    return resp

# remove idfavoris  from  favorites list
@customersapi.route('/customers/favoris/delete/<idfavoris>', methods=['PUT'])
@jwt_required()
def userRemoveFavoris(idfavoris):

    iduser = get_jwt_identity()
    
    if ObjectId.is_valid(idfavoris) == False:
        return id_inalid(idfavoris)

    user = customers.find_one({'_id': ObjectId(iduser)})
    prod = products.find_one({'_id': ObjectId(idfavoris)})
    # user of provier not exist in dataBase
    if user == None or prod == None:
        resp = jsonify({"message": "user or provider not exist"})
        resp.status_code = 404
        return resp
    
    # Exist: remove the favoris idfavoris
    try:
        customers.update_one({'_id': ObjectId(iduser)}, { '$pull': {"favoris": ObjectId(idfavoris)}})
    except Exception:
       abort(500)

    return success()

# add notification to the user "iduser"
@customersapi.route('/customers/notifications/add', methods=['PUT'])
@jwt_required()
def userAddnotification():

    iduser = get_jwt_identity()
    
    if not request.json:
        abort(400)
    if 'description' not in request.json:
        abort(400)
   
    user = customers.find_one({'_id': ObjectId(iduser)})
    # user of provier not exist in dataBase
    if user == None:
        resp = jsonify({"message": "user not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: update collection customers
    notfication = request.get_json()
    notfication['id'] = str(uuid.uuid1())

    notfication['date'] = time.strftime('%d/%m/%y', time.localtime())
    try:
        customers.update_one({'_id': ObjectId(iduser)}, {
                         '$push': {"notifications": notfication}})
    except Exception:
        message = {
            'status': 500,
            'message': 'update problem'
        }
        resp = jsonify(message)
        return resp

    return success()

# get All notifications of the user iduser
@customersapi.route('/customers/notifications', methods=['GET'])
@jwt_required()
def getNotifications():
  
    iduser = get_jwt_identity()
    
    notifications = customers.find({'_id': ObjectId(iduser)}, {"notifications": 1, '_id': 0})
    
    # user of provier not exist in dataBase
    if notifications == None:
        resp = jsonify({"message": "user not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: get notifications
    output = []
    for d in notifications:        
        output.append(json.loads(json_util.dumps(d)))
        
    resp = jsonify(output)
    resp.status_code = 200
    return resp

# delete all notifications
@customersapi.route('/customers/notifications/deleteAll', methods=['put'])
@jwt_required()
def deleteAllNotifications():

    iduser = get_jwt_identity()

    customer = customers.find_one({'_id': ObjectId(iduser)})
    if customer == None:
        return user_notfound(iduser)
    if 'notifications' not in customer:
        return jsonify({'msg': 'There is no notification'}), 404 
    
    try:
        res = customers.update_one({'_id': ObjectId(iduser)}, {'$set': {"notifications": []}})
    except Exception:
        abort(500)     

    return success()

# Delete the notification idNotification
@customersapi.route('/customers/notifications/deleteOne/<idNotification>', methods=['PUT'])
@jwt_required()
def deleteOneNotification(idNotification):

    idUser = get_jwt_identity()
    
    customer = customers.find_one({'_id': ObjectId(idUser)})

    if customer == None:
        return user_notfound(idUser)
    if 'notifications' not in customer:
        return jsonify({'msg': 'There is no notification'}), 404 
    try:        
        res = customers.update_one({'_id': ObjectId(idUser)}, {'$pull': {"notifications": {"id": idNotification}}})
    except Exception:
        abort(500)
       
    return success()
    
#####################################################
  #Order
#####################################################
# get All order of the user iduser
@customersapi.route('/customers/orders', methods=['GET'])
@jwt_required()
def getAllOrders():
  
    iduser = get_jwt_identity()
    orders = customers.find({'_id': ObjectId(iduser)}, {"orders": 1, '_id': 0})
    
    # user of provier not exist in dataBase
    if orders == None:
        resp = jsonify({"message": "user not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: get notifications
    output = []
    for d in orders:
        output.append(json.loads(json_util.dumps(d)))
    resp = jsonify(output)
    resp.status_code = 200
    return resp

# log In 
@customersapi.route('/customers/logIn', methods=['POST'])
def login():

    if not request.json:
        abort(400)
    if 'email' not in request.json or 'password' not in request.json:
        abort(400) 

    data = request.get_json()    
    user = customers.find_one({'email': data['email']})

    # Email not exist in dataBase
    if user == None:
        resp = jsonify({"message": "This Email not exist in database"})
        resp.status_code = 404
        return resp

    if check_password_hash(user['password'], data['password']):

        access_token = create_access_token(identity= str(user['_id']), fresh=True)
        refresh_token = create_refresh_token(identity= str(user['_id']))

        user['token'] = access_token
        user['refresh'] = refresh_token
        return jsonify({'ok': True, 'data': json.loads(json_util.dumps(user))}), 200
        
    else:
        resp = jsonify({'message' : 'Bad Request - invalid password'})
        resp.status_code = 400
        return resp

#refresh  token
@customersapi.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    ''' refresh token endpoint '''
    current_user = get_jwt_identity()
    ret = {
        'token': create_access_token(identity=current_user)
    }
    return jsonify({'ok': True, 'data': ret}), 200  


@customersapi.route('/customers/logOut/',  methods=['GET'])
@jwt_required()
def logout():

	current_user = get_jwt_identity()
	return jsonify({'message' : current_user})

@customersapi.route('/getAll/', methods=['GET'])
@jwt_required()
def allcustomers():
    
    output = []
    for d in customers.find().sort('created', -1):
        output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

# Admin management """"""""""""""""""""""""""
# Add Admin
@customersapi.route('/admin/register/', methods=['POST'])
def createAdmin():

    if not request.json:
        abort(400)
    if 'name' not in request.json or 'password' not in request.json or 'email' not in request.json:
        abort(400) 
        
    customer = request.get_json()
    user = admins.find_one({'email': customer['email']})
    if user:
        resp = jsonify({"message": "An account already registered by this Email"})
        resp.status_code = 404
        return resp
    
    customer['created'] = time.strftime('%d/%m/%y', time.localtime())
    customer['password'] = generate_password_hash(customer['password'])
    try:
        res = admins.insert_one(customer)
    except Exception:
        return internalServer()

    u = admins.find_one({'_id': ObjectId(res.inserted_id)}, {'password': 0} )
    resp = jsonify(json.loads(json_util.dumps(u)))
    resp.status_code = 200
    return resp

# Login Admin
@customersapi.route('/admin/logIn', methods=['POST'])
def loginAdmin():

    if not request.json:
        abort(400)
    if 'email' not in request.json or 'password' not in request.json:
        abort(400) 

    data = request.get_json()    
    user = admins.find_one({'email': data['email']})

    # Email not exist in dataBase
    if user == None:
        resp = jsonify({"message": "This Email not exist in database"})
        resp.status_code = 404
        return resp

    if check_password_hash(user['password'], data['password']):

        access_token = create_access_token(identity= str(user['_id']), fresh=True)
        refresh_token = create_refresh_token(identity= str(user['_id']))

        user['token'] = access_token
        user['refresh'] = refresh_token
        return jsonify({'ok': True, 'data': json.loads(json_util.dumps(user))}), 200
        
    else:
        resp = jsonify({'message' : 'Bad Request - invalid password'})
        resp.status_code = 400
        return resp

if __name__ == '__main__':
    app.run(debug=True)
