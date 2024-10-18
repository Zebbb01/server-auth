from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import psycopg2
from psycopg2 import sql, Error
import bcrypt
import re
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder='../frontend/build', static_url_path='/')
CORS(app, origins=["https://website-auth-react1.vercel.app", "http://localhost:5173"])

PEPPER = os.getenv('PEPPER')
DB_HOST = os.getenv('DB_HOST')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')
DB_PORT = os.getenv('DB_PORT')

# PostgreSQL connection setup
def create_connection():
    try:
        return psycopg2.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            dbname=DB_NAME,
            port=DB_PORT,
        )
    except Error as e:
        print(f"Database connection error: {e}")
        return None

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

def is_strong_password(password):
    if (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"\d", password) and
            re.search(r"[!@#$%^&*_()-,.?\":{}|<>]", password)):  # Include special characters
        return True
    return False

# To create a user
def create_user(password, pepper):
    # Combine password and pepper
    password_with_pepper = password + pepper
    # Hash the password and salt
    hashed_password = bcrypt.hashpw(password_with_pepper.encode('utf-8'), bcrypt.gensalt())
    return hashed_password  # return the hashed password for further processing

def migrate_user_table():
    conn = create_connection()
    if conn is None:
        return

    create_table_query = """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        pepper VARCHAR(100) NOT NULL
    );
    """
    
    try:
        cursor = conn.cursor()
        cursor.execute(create_table_query)
        conn.commit()
        print("Table 'users' created or already exists.")
    except Error as e:
        print(f"Error creating table: {e}")
    finally:
        cursor.close()
        conn.close()
        
migrate_user_table()
        

# Signup route
@app.route('/signup', methods=['POST'])
def signup():
    conn = create_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        cursor = conn.cursor()

        name = request.json['name']
        email = request.json['email']
        password = request.json['password']

        # Check if the email already exists
        cursor.execute(sql.SQL("SELECT * FROM users WHERE email = %s"), (email,))
        if cursor.fetchone():
            return jsonify({"error": "Email already exists"}), 409

        # Validate the password strength
        if not is_strong_password(password):
            return jsonify({"error": "Password must be at least 8 characters long and include upper, lower, digit, and special character"}), 400

        # Hashing password with pepper
        hashed_password = bcrypt.hashpw((password + PEPPER).encode('utf-8'), bcrypt.gensalt())

        # Store the hashed password as a string (not bytes)
        cursor.execute(sql.SQL("INSERT INTO users (name, email, password, pepper) VALUES (%s, %s, %s, %s)"),
                       (name, email, hashed_password.decode('utf-8'), PEPPER))  # Decode the bytes to string
        conn.commit()

        return jsonify({"message": "User created successfully"}), 201

    except Error as e:
        print(f"Error during signup: {e}")  # Log the error
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()


# Fetch user by email helper function
def fetch_user_by_email(email):
    conn = create_connection()
    if conn is None:
        return None

    try:
        cursor = conn.cursor()
        cursor.execute(sql.SQL("SELECT * FROM users WHERE email = %s"), (email,))
        user = cursor.fetchone()  # Fetch the user data
        return user  # This will return a tuple with user data
    except Error as e:
        print(f"Error fetching user: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Fetch user from the database
    user = fetch_user_by_email(email)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Extract stored hashed password and pepper
    stored_password = user[3]  # Assuming hashed_password is in the 3rd column
    pepper = user[4]  # Assuming pepper is in the 4th column

    # Check password
    if bcrypt.checkpw((password + pepper).encode('utf-8'), stored_password.encode('utf-8')):
        return jsonify({
            "message": "Login successful",
            "user": {
                "name": user[1],  # Assuming name is in the 1st column
                "email": user[2],  # Assuming email is in the 2nd column
                "password": password,  # Include the raw password for the dashboard
                "hashed_password": stored_password,  # Send hashed password
                "pepper": pepper  # Send pepper
            }
        }), 200
    else:
        return jsonify({"error": "Invalid password"}), 401

@app.route('/<path:path>')
def serve_static_files(path):
    return send_from_directory(app.static_folder, path)


if __name__ == '__main__':
    app.run(debug=True)
