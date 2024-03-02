from flask import Flask, jsonify, make_response, request
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import datetime
from psycopg2 import sql
import psycopg2
import bcrypt
import jwt
import os

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# postgreSQL database using psycopg2
db = psycopg2.connect(
    host=os.getenv("DB_LOCAL_HOST"),
    user=os.getenv("DB_LOCAL_USER"),
    password=os.getenv("DB_LOCAL_PASS"),
    database=os.getenv("DB_LOCAL_DB"),
)

cursor = db.cursor()

JWTSecretKey = os.getenv("DB_LOCAL_AUTH0_SECRET_KEY")
users = []

# test route server if server working
@app.route('/api/getData')
def get_data():
    data = {'message': 'Hello from Python server!'}
    return jsonify(data)

# ------------------------------------------------------------------------------------------
# register route
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    firstName = data.get("firstName")
    lastName = data.get("lastName")
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    salt = bcrypt.gensalt(10)
    password_bytes = password.encode('utf-8')
    hash_password = bcrypt.hashpw(password_bytes, salt)
    password_hash_str = hash_password.decode()

    new_user = {
        "id": len(users) + 1, 
        'username': username, 
        'password': hash_password, 
        "salt": salt
    }
    users.append(new_user)

    token_bytes = jwt.encode({'id': new_user["id"], 'username': new_user["username"]}, JWTSecretKey, algorithm='HS256')
    token = token_bytes

    first_name = firstName
    last_name = lastName
    email = email
    username = username
    get_password = password_hash_str
    created_date = datetime.utcnow().isoformat()

    if not email: 
        return jsonify({"error": "✖ EMAIL ALREADY EXISTS"}), 400
    
    # Inserting data into the "register" table
    query = sql.SQL("""INSERT INTO register (first_name, last_name, email, username, password, created_date)
    VALUES (%s, %s, %s, %s, %s, %s)""")

    cursor.execute(query, (first_name, last_name, email, username, get_password, created_date))
    db.commit() 

    response = make_response(jsonify({'message': 'REGISTER SUCCESSFUL', 'token': token}), 200)
    response.set_cookie("token", token, httponly=True)
    return response

# ------------------------------------------------------------------------------------------

# login route
@app.route("/api/login", methods=["POST"])
def login():
    # get data from body
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    cursor.execute("SELECT * FROM register WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'error': '✖ USERNAME NOT FOUND'}), 401

    # Check if entered password matches stored hashed password
    if not bcrypt.checkpw(password.encode('utf-8'), user[5].encode('utf-8')):
        return jsonify({'error': '✖ INCORRECT PASSWORD'}), 401

    cursor.execute("INSERT INTO login (username, password) VALUES (%s, %s)", (username, user[5]))
    db.commit()

    token_bytes = jwt.encode({'id': user[0], 'username': user[2]}, JWTSecretKey, algorithm='HS256')
    token = token_bytes

    response = make_response(jsonify({'message': 'LOGIN SUCCESSFUL', 'token': token}), 200)
    response.set_cookie("token", token, httponly=True)

    return response

# ------------------------------------------------------------------------------------------

# logout route
@app.route("/api/logout", methods=["POST"])
def logout():
    response = make_response(jsonify({"message": "Logout Successful"}), 200)
    response.delete_cookie("token")
    return response

# ------------------------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)


# renders an index html page
# @app.route('/') 
# def home():
#     return render_template('index.html')