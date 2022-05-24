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

#get max date as product is new
@settingsapi.route('/settings/newArrivalDay/', methods=['GET'])
def allNew():

    metrics = settings.find_one({},{"days": 1})   
    resp = jsonify(json.loads(json_util.dumps(metrics)))
    resp.status_code=200
    return resp

#get All settings
@settingsapi.route('/settings/getAll', methods=['GET'])
def allSettings(): 
    
    set = settings.find_one()   
    resp = jsonify(json.loads(json_util.dumps(set)))
    resp.status_code=200
    return resp


if __name__ == '__main__':
    app.run(debug=True)

