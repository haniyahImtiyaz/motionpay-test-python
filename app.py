import hashlib
import datetime
import os
import re
from uuid import UUID, uuid4
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from pymongo import MongoClient

app = Flask(__name__)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
app.config['JSON_SORT_KEYS'] = False

client = MongoClient(os.getenv("MONGODB_URI"), uuidRepresentation="standard")
db = client[os.getenv("DB_NAME")]

users_collection = db["users"]
transaction_collection = db["transactions"]


@app.route("/register", methods=["POST"])
def register():
    request_all = request.get_json()
    request_all["pin"] = hashlib.sha256(
        request_all["pin"].encode("utf-8")).hexdigest()
    user_exist = users_collection.find_one(
        {"phone_number": request_all["phone_number"]})

    if not user_exist:

        regex_phone = bool(re.match("^[0-9]*$", request_all['phone_number']))
        if not bool(regex_phone):
            return jsonify({
                'status': 'FAIL',
                'message': 'Phone Number not valid'
            }), 422

        
        request_all['_id'] = uuid4()
        request_all['created_date'] = datetime.datetime.now()
        new_user = users_collection.insert_one(request_all)
        result = {
            'status': 'SUCCESS',
            'result': {
                'user_id': str(new_user.inserted_id),
                'first_name': request_all['first_name'],
                'last_name': request_all['last_name'],
                'phone_numer': request_all['phone_number'],
                'address': request_all['address'],
                'created_date': request_all['created_date'].strftime('%Y-%m-%d %H:%M:%S')
            }
        }
        return jsonify(result), 201
    else:
        return jsonify({
            'status': 'FAIL',
            'message': 'Phone Number already registered'
        }), 409


@app.route("/login", methods=["POST"])
def login():
    request_all = request.get_json()
    user = users_collection.find_one(
        {'phone_number': request_all['phone_number']})

    if user:
        encrpted_password = hashlib.sha256(
            request_all['pin'].encode("utf-8")).hexdigest()
        if encrpted_password == user['pin']:
            access_token = create_access_token(identity=user['phone_number'])
            refresh_token = create_refresh_token(identity=user['phone_number'])
            return jsonify({
                'status': 'SUCCESS',
                'result': {
                    'access_token': access_token,
                    'refresh_token': refresh_token
                }
            }), 200

    return jsonify({
        'status': 'FAIL',
        'message': "Phone number and pin doesn't match."
    }), 401


@app.route("/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    request_all = request.get_json()
    current_user = get_jwt_identity()
    user = users_collection.find_one({'phone_number': current_user})
    if user:
        data_update = {}
        if 'first_name' in request_all:
            data_update['first_name'] = request_all['first_name']
            
        if 'last_name' in request_all:
            data_update['last_name'] = request_all['last_name']
            
        if 'address' in request_all:
            data_update['address'] = request_all['address']
            
        if 'pin' in request_all:
            request_all["pin"] = hashlib.sha256(
                request_all["pin"].encode("utf-8")).hexdigest()
            data_update['pin'] = request_all['pin']
        
        data_update['updated_date'] = datetime.datetime.now()

        users_collection.update_one({'_id' : user['_id']}, {"$set" : data_update})
        user = users_collection.find_one({'_id': user['_id']})

        result = {
            'status' : 'SUCCESS',
            'result' : {
                'user_id' : str(user['_id']),
                'first_name' : user['first_name'],
                'last_name' : user['last_name'],
                'address' : user['address'],
                'updated_date': data_update['updated_date'].strftime('%Y-%m-%d %H:%M:%S')
            }
        }
        return jsonify(result), 200
    else:
        return jsonify({
            'status': 'FAIL',
            'message': "Phone number and pin doesn't match."
        }), 401


@app.route("/topup", methods=["POST"])
@jwt_required()
def topup():
    request_all = request.get_json()
    current_user = get_jwt_identity()
    user = users_collection.find_one({'phone_number': current_user})
    if user:
        if(request_all['amount'] <= 0 ):
            return jsonify({
                'status': 'FAIL',
                'message': 'Amount must be greater than 0.'
            }), 422

        log_before = transaction_collection.find_one(
            {'user_id': user['_id']}, sort=[('created_date', -1)])
        if log_before:
            balance_before = log_before['balance_after']
        else:
            balance_before = 0

        balance_after = int(balance_before) + int(request_all['amount'])

        top_up_id = uuid4()
        data_insert = {}
        data_insert['_id'] = uuid4()
        data_insert['top_up_id'] = top_up_id
        data_insert['status'] = 'SUCCESS'
        data_insert['user_id'] = user['_id']
        data_insert['transaction_type'] = 'CREDIT'
        data_insert['amount'] = request_all['amount']
        data_insert['remarks'] = ''
        data_insert['balance_before'] = balance_before
        data_insert['balance_after'] = balance_after
        data_insert['created_date'] = datetime.datetime.now()

        transaction_collection.insert_one(data_insert)

        result = {
            'status': 'SUCCESS',
            'result': {
                'top_up_id': str(top_up_id),
                'amount_top_up': request_all['amount'],
                'balance_before': balance_before,
                'balance_after': balance_after,
                'created_date': data_insert['created_date'].strftime('%Y-%m-%d %H:%M:%S')
            }
        }

        return jsonify(result), 200
    else:
        return jsonify({
            'status': 'FAIL',
            'message': 'User not registered.'
        }), 404


@app.route("/pay", methods=["POST"])
@jwt_required()
def pay():
    request_all = request.get_json()
    current_user = get_jwt_identity()
    user = users_collection.find_one({'phone_number': current_user})
    if user:
        if(request_all['amount'] <= 0 ):
            return jsonify({
                'status': 'FAIL',
                'message': 'Amount must be greater than 0.'
            }), 422

        total_balance = 0
        log_balances = transaction_collection.find(
            {'user_id': user['_id']}).sort('created_date', -1)

        index = 0
        for log in log_balances:
            if log['transaction_type'] == 'DEBIT':
                log['amount'] =  -log['amount']
            total_balance += log['amount']
            if(index == 0):
                balance_before = log['balance_after']
            index = + 1

        if(total_balance < request_all['amount']):
            return jsonify({
                'status': 'FAIL',
                'message': 'Balance is not enough'
            }), 422

        balance_after = int(balance_before) - int(request_all['amount'])

        payment_id = uuid4()
        data_insert = {}
        data_insert['_id'] = uuid4()
        data_insert['payment_id'] = payment_id
        data_insert['status'] = 'SUCCESS'
        data_insert['user_id'] = user['_id']
        data_insert['transaction_type'] = 'DEBIT'
        data_insert['amount'] = request_all['amount']
        data_insert['remarks'] = ''
        data_insert['balance_before'] = balance_before
        data_insert['balance_after'] = balance_after
        data_insert['created_date'] = datetime.datetime.now()
        data_insert['remarks'] = request_all['remarks']

        transaction_collection.insert_one(data_insert)

        result = {
            'status': 'SUCCESS',
            'result': {
                'payment_id': str(payment_id),
                'amount': request_all['amount'],
                'remarks': request_all['remarks'],
                'balance_before': balance_before,
                'balance_after': balance_after,
                'created_date': data_insert['created_date'].strftime('%Y-%m-%d %H:%M:%S')
            }
        }

        return jsonify(result), 200
    else:
        return jsonify({
            'status': 'FAIL',
            'message': 'User not registered.'
        }), 404


@app.route("/transfer", methods=["POST"])
@jwt_required()
def transfer():
    request_all = request.get_json()
    current_user = get_jwt_identity()
    user = users_collection.find_one({'phone_number': current_user})
    if user:
        if(request_all['amount'] <= 0 ):
            return jsonify({
                'status': 'FAIL',
                'message': 'Amount must be greater than 0.'
            }), 422

        target_user = users_collection.find_one({'_id': UUID(request_all['target_user'])})
        if not target_user:
            return jsonify({
                'status': 'FAIL',
                'message': 'Target user not found.'
            }), 422

        total_balance = 0
        log_balances = transaction_collection.find(
            {'user_id': user['_id']}).sort('created_date', -1)

        index = 0
        for log in log_balances:
            if(log['transaction_type'] == 'DEBIT'):
                log['amount'] = -log['amount']

            total_balance += log['amount']

            if(index == 0):
                balance_before = log['balance_after']
            index = + 1

        if(total_balance < request_all['amount']):
            return jsonify({
                'status': 'FAIL',
                'message': 'Balance is not enough'
            }), 422

        balance_after = int(balance_before) - int(request_all['amount'])

        transfer_id = uuid4()
        data_insert = {}
        data_insert['_id'] = uuid4()
        data_insert['transfer_id'] = transfer_id
        data_insert['status'] = 'SUCCESS'
        data_insert['user_id'] = user['_id']
        data_insert['transaction_type'] = 'DEBIT'
        data_insert['amount'] = request_all['amount']
        data_insert['remarks'] = request_all['remarks']
        data_insert['balance_before'] = balance_before
        data_insert['balance_after'] = balance_after
        data_insert['created_date'] = datetime.datetime.now()

        transaction_collection.insert_one(data_insert)

        # insert log for target user    
        log_before = transaction_collection.find_one(
            {'user_id': target_user['_id']}, sort=[('created_date', -1)])
        if log_before:
            balance_before_target = log_before['balance_after']
        else:
            balance_before_target = 0

        balance_after_target = int(balance_before_target) + int(request_all['amount'])

        data_insert = {}
        data_insert['_id'] = uuid4()
        data_insert['transfer_id'] = uuid4()
        data_insert['status'] = 'SUCCESS'
        data_insert['user_id'] = target_user['_id']
        data_insert['transaction_type'] = 'CREDIT'
        data_insert['amount'] = request_all['amount']
        data_insert['remarks'] = request_all['remarks']
        data_insert['balance_before'] = balance_before_target
        data_insert['balance_after'] = balance_after_target
        data_insert['created_date'] = datetime.datetime.now()

        transaction_collection.insert_one(data_insert)

        result = {
            'status': 'SUCCESS',
            'result': {
                'payment_id': str(transfer_id),
                'amount': request_all['amount'],
                'remarks': request_all['remarks'],
                'balance_before': balance_before,
                'balance_after': balance_after,
                'created_date': data_insert['created_date'].strftime('%Y-%m-%d %H:%M:%S')
            }
        }

        return jsonify(result), 200
    else:
        return jsonify({
            'status': 'FAIL',
            'message': 'User not registered.'
        }), 404


@app.route("/transactions", methods=["GET"])
@jwt_required()
def transaction_list():
    current_user = get_jwt_identity()
    user = users_collection.find_one({'phone_number': current_user})
    if user:
        data = list(transaction_collection.find({'user_id' : user['_id']}))

        result = {
            'status' : 'SUCCESS',
            'result' : data
        }
        
        return jsonify(result), 200

    return jsonify({
        'status': 'FAIL',
        'message': 'User not registered.'
    }), 404


if __name__ == '__main__':
    app.run(debug=True)
