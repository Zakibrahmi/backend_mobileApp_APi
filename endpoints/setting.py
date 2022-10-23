#from apicore import api, Http501Exception
from flask import request, make_response, abort, Blueprint
from flask import Flask 
from flask import jsonify
from flask_pymongo import PyMongo
import os
from werkzeug.utils import secure_filename
import json
from flask.json import jsonify
from bson.objectid import ObjectId
from bson import objectid, json_util
import time

from endpoints.utilsFunction import *
from . import *

app = Flask(__name__)
settingsapi = Blueprint(name="settingsapi", import_name=__name__)


#traitement erreur 
@settingsapi.errorhandler(400)
def create_failed(error):
  return make_response(jsonify({"error": "bad input"}), 400)
  
@settingsapi.errorhandler(500)
def internalServer(error):
  return make_response(jsonify({'error': 'Internal Server Error' }), 500)

@settingsapi.errorhandler(403)
def typenotfound(id, type):
    message = {
               'status': 403,
               'message': type +' not Found: ' +  str(id),
             }
    resp = jsonify(message)
    return resp


@settingsapi.errorhandler(404)
def not_found(error=None):
    message = {
               'status': 404,
               'message': 'Not Found: ' + request.url,
             }
    resp = jsonify(message)
    resp.status_code = 404
    return resp

# add/Update settings. If seetings exist, all settings need to be send and request
@settingsapi.route('/admin/settings/add', methods=['POST'])
def addUpdateSetting():

    if not request.json:
        abort(400)
    settings.drop()
    data= request.get_json()
    if  "daysToReturns" not in request.json:
        data ["daysToReturns"] = 15
    if "reasons" not in request.json:
        data ["reasons"] = []
    if "estimateDaysDeliveryIn" not in request.json: 
        data["estimateDaysDeliveryIn"] = 2
    if "estimateDaysDeliveryOut" not in request.json: 
        data["estimateDaysDeliveryOut"] = 5
    if "orderIn" not in request.json: 
        data["orderInHours"] = 15
    try:
        pro = settings.insert_one(data)
    except Exception:
        abort(500)
      
    set = settings.find_one({'_id': ObjectId(pro.inserted_id)})
    resp = jsonify(json.loads(json_util.dumps(set)))
    resp.status_code= 200
    return resp

#get all settings
@settingsapi.route('/admin/settings/all', methods=['GET'])
def allSettings(): 
    
    output = []
    for d in settings.find():
      output.append(json.loads(json_util.dumps(d)))
    resp = jsonify(output)
    resp.status_code = 200
    return resp
  
#get raison settings
@settingsapi.route('/admin/settings/reasons', methods=['GET'])
def reasonsSettings(): 
    
    rai = settings.find_one({}, {"reasons": 1, "_id": 0})   
    resp = jsonify(json.loads(json_util.dumps(rai)))
    resp.status_code=200
    return resp
  
# Get days to return settings
@settingsapi.route('/admin/settings/daysToReturns', methods=['GET'])
def getDaysSettings(): 
    
    dy = settings.find_one({}, {"daysToReturns": 1, "_id": 0})   
    resp = jsonify(json.loads(json_util.dumps(dy)))
    resp.status_code=200
    return resp

#get estimateDaysDelivery Inside Bahrain
@settingsapi.route('/admin/settings/estimateDaysDeliveryIn', methods=['GET'])
def reasonsSettings(): 
    
    rai = settings.find_one({}, {"estimateDaysDeliveryIn": 1, "_id": 0})   
    resp = jsonify(json.loads(json_util.dumps(rai)))
    resp.status_code=200
    return resp

#get estimateDaysDelivery out Bahrain
@settingsapi.route('/admin/settings/estimateDaysDeliveryPut', methods=['GET'])
def reasonsSettings(): 
    
    rai = settings.find_one({}, {"estimateDaysDeliveryOut": 1, "_id": 0})   
    resp = jsonify(json.loads(json_util.dumps(rai)))
    resp.status_code=200
    return resp
if __name__ == '__main__':
    app.run(debug=True)

