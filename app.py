from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import bcrypt
import re
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder='../frontend/build', static_url_path='/')
CORS(app, origins=["https://website-auth-react1.vercel.app"])


PEPPER = os.getenv('PEPPER')
DB_HOST = os.getenv('DB_HOST')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')

# MySQL connection setup
def create_connection():
    try:
        return mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
    except Error as e:
        print(f"Error: {e}")
        return None

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

def is_strong_password(password):
    if (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"\d", password) and
            re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):  # Include special characters
        return True
    return False

@app.route('/signup', methods=['POST'])
def signup():
    conn = create_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = conn.cursor()

    try:
        name = request.json['name']
        email = request.json['email']
        password = request.json['password']

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "Email already exists"}), 409

        if not is_strong_password(password):
            return jsonify({"error": "Password must be at least 8 characters long and include upper, lower, digit, and special character"}), 400

        hashed_password = bcrypt.hashpw((password + PEPPER).encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (name, email, password, pepper) VALUES (%s, %s, %s, %s)",
                       (name, email, hashed_password, PEPPER))
        conn.commit()

        return jsonify({"message": "User created successfully"}), 201

    except Error as e:
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    conn = create_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = conn.cursor()

    try:
        email = request.json['email']
        password = request.json['password']

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            stored_password = user[3]
            pepper = user[4]

            if bcrypt.checkpw((password + pepper).encode('utf-8'), stored_password.encode('utf-8')):
                return jsonify({
                    "message": "Login successful",
                    "user": {
                        "name": user[1],
                        "email": user[2],
                    }
                }), 200
            else:
                return jsonify({"error": "Incorrect password"}), 401
        else:
            return jsonify({"error": "User not found"}), 404

    except Error as e:
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/<path:path>')
def serve_static_files(path):
    return send_from_directory(app.static_folder, path)

if __name__ == '__main__':
    app.run(debug=True)
