from bson.objectid import ObjectId

from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask import Flask, Blueprint, jsonify

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'waedlineDB'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/waedLineDB'
#app.config['MONGO_URI']= 'mongodb://waedLine:jCRF3Tmp3k6lgvhC@cluster0-shard-00-00.revzv.mongodb.net:27017,cluster0-shard-00-01.revzv.mongodb.net:27017,cluster0-shard-00-02.revzv.mongodb.net:27017/waedlineDB?ssl=true&replicaSet=atlas-46f9og-shard-0&authSource=admin&retryWrites=true&w=majority'
mongo = PyMongo(app)
customers = mongo.db.customers
products = mongo.db.products
settings = mongo.db.settings
categories = mongo.db.categories
collections = mongo.db.collections


