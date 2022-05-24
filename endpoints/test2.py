from flask import Flask, Blueprint, jsonify, request

from flask_pymongo import PyMongo
from flask import request, make_response, abort

from flask import Flask, Blueprint, jsonify

from flask_pymongo import PyMongo
import os
import pymongo
from werkzeug.utils import secure_filename
import json
from flask.json import jsonify
from bson.objectid import ObjectId
from bson import objectid, json_util

app = Flask(__name__)
# define the blueprint
test = Blueprint(name="test", import_name=__name__)


app.config['MONGO_DBNAME'] = 'masterfixDB'
app.config['MONGO_URI'] = 'mongodb://masterfix:w5anJSwc1NhLJAnS@cluster0.iwl07.mongodb.net/masterfixDB?retryWrites=true&w=majority'
mongo = PyMongo(app)
users = mongo.db.users

@test.route('/test/', methods=['GET'])
def example():
       
    output = []
    try:
        for d in users.find():
             output.append(json.loads(json_util.dumps(d)))  
    except pymongo.errors.OperationFailure as e: 
        return  jsonify( {json.loads(json_util.dumps(e.message))})

    resp = jsonify( json.loads(json_util.dumps(output)))
    resp.status_code = 200
    return resp
    