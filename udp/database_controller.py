from pymongo import MongoClient
import pprint

class DatabaseController():

    def __init__(self, port):
        self.client = MongoClient('localhost', 27017) # client = MongoClient()
        self.db = self.client['blockchain'] # or db = client.test_database
        self.collection = ''
        self.set_collection(port)

    def set_collection(self, port):
        collection_name = 'blockchain_' + str(port) 
        self.collection = self.db[collection_name] # collection = db.test_collection
        self.collection.remove(None)

    def insert_data(self, data):
        posts = self.collection
        post_id = posts.insert_one(data).inserted_id # insert data

        self.db.collection_names(include_system_collections=False) # verify the post
        # pprint.pprint(posts.find_one({"author": "Mike"})) # or by object id {"_id": post_id}
