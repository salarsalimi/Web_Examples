from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Configure the JWT secret key
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
jwt = JWTManager(app)

# In-memory user storage
users = {
    'user1': {'password': 'password1', 'name': 'User One', 'user_type': 'admin'},
    'user2': {'password': 'password2', 'name': 'User Two', 'user_type': 'viewer'},
    'user3': {'password': 'password3', 'name': 'User Three', 'user_type': 'viewer'}
}

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    user = users.get(username, None)
    if user and user['password'] == password:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@app.route('/api/me', methods=['GET'])
@jwt_required()
def me():
    current_user = get_jwt_identity()
    user_info = users.get(current_user, {})
    if not user_info:
        return jsonify({"msg": "User not found"}), 404

    return jsonify(name=user_info['name'], user_type=user_info['user_type']), 200

@app.route('/')
@jwt_required()
def index():
    return '<h1>Welcome to the blank page!</h1>', 200

if __name__ == '__main__':
    app.run(host="example.com", port=int(4000), debug=True)
