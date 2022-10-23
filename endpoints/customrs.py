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
    if isinstance(request.json['email'], str) == False:
        abort(400)
    if 'mobile' not in request.json:
        abort(400)

    customer = request.get_json()
    user = customers.find_one({'email': customer['email']})
    if user:
        resp = jsonify({"message": "An account already registered by this Email"})
        resp.status_code = 404
        return resp
    
    customer['create'] = time.strftime('%d/%m/%y', time.localtime())
    customer['password'] = generate_password_hash(customer['password'])
    try:
        res = customers.insert_one(customer)
    except Exception:
        return internalServer()

    user = customers.find_one({'_id': ObjectId(res.inserted_id)}, {'password': 0} )
    resp = jsonify(json.loads(json_util.dumps(user)))
    
    access_token = create_access_token(identity= str(user['_id']), fresh=True)
    refresh_token = create_refresh_token(identity= str(user['_id']))
   
    user['token'] = access_token
    user['refresh'] = refresh_token
    return jsonify({'ok': True, 'user': json.loads(json_util.dumps(user))}), 200

# update  customer account
@customersapi.route('/customers/<id>/', methods=['PUT'])
#@jwt_required(refresh=True)
def updateCustomer(id):

    if not request.json:
        abort(400)
  
    if 'password' not in request.json  and 'mobile' not in request.json:
        abort(400) 
    if 'name' in request.json and isinstance(request.json['name'], str) == False:
        abort(400)
   
    if 'mobile' in request.json and isinstance(request.json['mobile'], str) == False:
        abort(400)
    
    customer = request.get_json()
    #customerId = get_jwt_identity()
    customer['password'] = generate_password_hash(customer['password'])
    
    try:
        res = customers.update_one({'_id': ObjectId(id)}, {'$set': customer})
    except Exception:
        abort(500)
    
    return jsonify(json.loads(json_util.dumps(customers.find_one({'_id': ObjectId(id)}))))


# get customer by ID
@customersapi.route('/customers/get/<iduser>', methods=['GET'])
def getUserByID(iduser):

    cost = customers.find_one({'_id': ObjectId(iduser)})
    resp = jsonify(json.loads(json_util.dumps(cost)))
    resp.status_code = 200
    return resp


# update shipping adress
@customersapi.route('/users/update/shippingAdress/<id>/', methods=['PUT'])
#@jwt_required()
def updateAdress(id):
    
    decison = token_required_user(request.headers)
    if decison != "authorized":
        return jsonify({'message': decison}), 401
    if not request.json:
        abort(400)

    #idCutomer = get_jwt_identity()
    try:
        res = customers.update_one({'_id': ObjectId(id)}, {'$set': {"shippingAdress": request.get_json()}})
    except Exception:
        abort(500)

    if res.modified_count == 0:
        return user_notfound(id)
    
    return jsonify(json.loads(json_util.dumps(customers.find_one({'_id': ObjectId(id)}))))

# update phone number
@customersapi.route('/users/update/phone/<id>', methods=['PUT'])
#@jwt_required()
def updatePhone(id):

    if not request.json:
        abort(400)
    #idCutomer = get_jwt_identity()    
    mobile = request.get_json()
    try:
        res = customers.update_one({'_id': ObjectId(id)}, {'$set': {"mobile": mobile['mobile']}})
    except Exception:
        abort(500)

    if res.modified_count == 0:
        return user_notfound(id)
    
    return jsonify(json.loads(json_util.dumps(customers.find_one({'_id': ObjectId(id)}))))

# add the  favoris product  "idfavoris" to the favorites list of the custorm  idcustomer
@customersapi.route('/customers/favoris/<idfavoris>/<idc>/', methods=['PUT'])
#@jwt_required()
def customerAddFavoris(idfavoris, idc):

    #idcustomer = get_jwt_identity()
    if ObjectId.is_valid(idfavoris) == False:
        return id_inalid(idfavoris)
    if ObjectId.is_valid(idc) == False:
        return id_inalid(idc)

    user = customers.find_one({'_id': ObjectId(idc)})
    product = products.find_one({'_id': ObjectId(idfavoris)})
    # user of provier not exist in dataBase
    if user == None or product == None:
        resp = jsonify({"message": "customer or product not exist"})
        resp.status_code = 404
        return resp
    # Exist: update collection user
    try:
        customers.update_one({'_id': ObjectId(idc)}, {'$addToSet': {"favoris": ObjectId(idfavoris)}})
    except Exception:
        return jsonify({"message": "update failed "})
    
    return jsonify(json.loads(json_util.dumps(customers.find_one({'_id': ObjectId(idc)}))))


# get All user favorites
@customersapi.route('/customers/favoris/<id>/', methods=['GET'])
#@jwt_required()
def getFavoris(id):

    #iduser = get_jwt_identity()
    favoris = customers.find_one({'_id': ObjectId(id)}, {"favoris": 1, '_id':0})
    # user of provier not exist in dataBase
    if favoris == None:
        resp = jsonify({"message": "user not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: get notifications
    output = []
    if "favoris" in favoris:
        for f in favoris['favoris']:
            output.append(json.loads(json_util.dumps(products.find_one({'_id': ObjectId(f)}))))
       #output.append(json.loads(json_util.dumps(f)))
    
    resp = jsonify(output)
    resp.status_code = 200
    return resp

# remove idfavoris  from  favorites list
@customersapi.route('/customers/favoris/delete/<idc>/<idfavoris>', methods=['PUT'])
#@jwt_required()
def userRemoveFavoris(idc, idfavoris):

    #iduser = get_jwt_identity()
    
    if ObjectId.is_valid(idfavoris) == False:
        return id_inalid(idfavoris)

    user = customers.find_one({'_id': ObjectId(idc)})
    prod = products.find_one({'_id': ObjectId(idfavoris)})
    # user of provier not exist in dataBase
    if user == None or prod == None:
        resp = jsonify({"message": "user or provider not exist"})
        resp.status_code = 404
        return resp
    
    # Exist: remove the favoris idfavoris
    try:
        customers.update_one({'_id': ObjectId(idc)}, { '$pull': {"favoris": ObjectId(idfavoris)}})
    except Exception:
       abort(500)

    return jsonify(json.loads(json_util.dumps(customers.find_one({'_id': ObjectId(idc)}))))

# add notification to the user "iduser"
@customersapi.route('/customers/notifications/add/<id>/', methods=['PUT'])
#@jwt_required()
def userAddnotification(id):

    #iduser = get_jwt_identity()
    
    if not request.json:
        abort(400)
    if 'description' not in request.json:
        abort(400)
   
    user = customers.find_one({'_id': ObjectId(id)})
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
        customers.update_one({'_id': ObjectId(id)}, {
                         '$push': {"notifications": notfication}})
    except Exception:
        message = {
            'status': 500,
            'message': 'update problem'
        }
        resp = jsonify(message)
        return resp

    return jsonify(json.loads(json_util.dumps(customers.find_one({'_id': ObjectId(id)}))))

# get All notifications of the user iduser
@customersapi.route('/customers/notifications/<id>/', methods=['GET'])
#@jwt_required()
def getNotifications(id):
  
    #iduser = get_jwt_identity()
    
    notifications = customers.find({'_id': ObjectId(id)}, {"notifications": 1, '_id': 0})
    
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
@customersapi.route('/customers/notifications/deleteAll/<id>/', methods=['put'])
#@jwt_required()
def deleteAllNotifications(id):

    #iduser = get_jwt_identity()

    customer = customers.find_one({'_id': ObjectId(id)})
    if customer == None:
        return user_notfound(IDENTIFIER)
    if 'notifications' not in customer:
        return jsonify({'msg': 'There is no notification'}), 404 
    
    try:
        res = customers.update_one({'_id': ObjectId(id)}, {'$set': {"notifications": []}})
    except Exception:
        abort(500)     

    return jsonify(json.loads(json_util.dumps(customers.find_one({'_id': ObjectId(id)}))))

# Delete the notification idNotification
@customersapi.route('/customers/notifications/deleteOne/<idc>/<idNotification>', methods=['PUT'])
#@jwt_required()
def deleteOneNotification(idc, idNotification):

    #idUser = get_jwt_identity()
    
    customer = customers.find_one({'_id': ObjectId(idc)})

    if customer == None:
        return user_notfound(idc)
    if 'notifications' not in customer:
        return jsonify({'msg': 'There is no notification'}), 404 
    try:        
        res = customers.update_one({'_id': ObjectId(idc)}, {'$pull': {"notifications": {"id": idNotification}}})
    except Exception:
        abort(500)
       
    return jsonify(json.loads(json_util.dumps(customers.find_one({'_id': ObjectId(idc)}))))
    

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
#@jwt_required()
def logout():

	current_user = get_jwt_identity()
	return jsonify({'message' : current_user})

@customersapi.route('/customers/getAll/', methods=['GET'])
#@jwt_required()
def allcustomers():

    page = request.args.get("page")
   
    limitcollection = request.args.get('limit')
    startIndex = (int(page) - 1) * int(limitcollection)
        
    cust = ['created', -1]    

    # filter orders; get document counts
    output = []
    results = customers.find().sort(cust[0], cust[1]).limit(int(limitcollection)).skip(startIndex)
    output = []
    for d in results:
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

#Update Email
@customersapi.route('/admin/updateEMail', methods=['PUT'])
def updateEmailAdmin():

    if not request.json:
        abort(400)
    if 'email' not in request.json:
        abort(400) 

    data = request.get_json()    
    user = admins.find_one({'_id': ObjectId(data['id'])})

    # Email not exist in dataBase
    if user == None:
        resp = jsonify({"message": "This user doesn't exist in database"})
        resp.status_code = 404
        return resp
    #udpate Email
    try:
        res = admins.update_one({'_id': ObjectId(data['id'])}, {'$set': {"email": data['email']}})
    except Exception:
        abort(500)  
        
    u = admins.find_one({'_id': ObjectId(data['id'])}, {'password': 0} )
    resp = jsonify(json.loads(json_util.dumps(u)))
    resp.status_code = 200
    return resp

#Update PW
@customersapi.route('/admin/updatePW', methods=['PUT'])
def updatePWAdmin():
    
    if not request.json:
        abort(400)
    if 'password' not in request.json:
        abort(400) 

    data = request.get_json()    
    user = admins.find_one({'_id': ObjectId(data['id'])})

    # Email not exist in dataBase
    if user == None:
        resp = jsonify({"message": "This user doesn't exist in database"})
        resp.status_code = 404
        return resp
    
    #udpate PW
    password = generate_password_hash(user['password'])
    try:
        res = admins.update_one({'_id': ObjectId(data['id'])}, {'$set': {"password": password}})
    except Exception:
        abort(500)  
        
    resp = jsonify({'message' : 'PW successfully updated'})
    resp.status_code = 200
    return resp

if __name__ == '__main__':
    app.run(debug=True)
