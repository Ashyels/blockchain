from application.blockchain import *

# Instantiate the Node
app = Flask(__name__)
app.debug = True
# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

import application.router