# Blockchain

Blockchain basic components:
1. Distributed Ledger
2. Consensus Mehchanism
3. Network Participants
3. Digital Asset

## Setting environment

Use Python 3
```
pip install flask
pip install requests
```

## How to use

### Run The node

open four command prompts and run
```
python main.py -p 5000		// for cmd (node) 1
python main.py -p 5001		// for cmd (node) 2
python main.py -p 5002		// for cmd (node) 3
python main.py -p 5003		// for cmd (node) 4
```

### Register the node list

post to `http://localhost:500(x)/nodes/register` for each node (x) with data:
```
{
	"nodes": [
		"http://127.0.0.1:500(x+1)",
		"http://127.0.0.1:500(x+2)",
		"http://127.0.0.1:500(x+3)",
	]
}
```

### Add new transaction

post to `http://localhost:500(x)/transactions/new` with data:
```
{
	"sender": "ed447b10b54c1ccbf0adffad50421770",
	"recipient": "4eeccab0e8c08e16a1d08296265e38fa",
	"amount": 5
}
```

### Add the new transaction to ledger (mining)

get to `http://localhost:500(x)/mine`

### Get the node (x) ledger

get to `http://localhost:500(x)/chain`

### Update node (x+1) ledger (to the longest ledger from node x)

get to `http://localhost:500(x+1)/nodes/resolve`

## Original Project Author

[Daniel van Flymen](https://github.com/dvf/blockchain)

## Continue Project Authors

1. [Ifan](https://github.com/ifandhanip)
2. [Tria](https://github.com/TriaYudaPurnama)

We continue the development using base [Blockchain Project](https://github.com/dvf/blockchain) with Latest commit 250a01c on Jan 27
