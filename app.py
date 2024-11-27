# Complete Flask Application for Secure File Sharing (as provided in the initial response)

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import bcrypt
import jwt
import os
from io import BytesIO

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///files.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    iv = db.Column(db.String(100), nullable=False)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    user = User(username=data['username'], password=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
        token = jwt.encode({'username': user.username}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/upload', methods=['POST'])
def upload_file():
    token = request.headers.get('Authorization').split()[1]
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_token['username']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    file = request.files['file']
    key = os.urandom(16)  # Random AES key
    iv = os.urandom(16)  # Random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(file.read(), AES.block_size))

    new_file = File(filename=file.filename, file_data=encrypted_data, iv=base64.b64encode(iv).decode('utf-8'))
    db.session.add(new_file)
    db.session.commit()

    return jsonify({'message': 'File uploaded successfully'})

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    token = request.headers.get('Authorization').split()[1]
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_token['username']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    file = File.query.filter_by(filename=filename).first()
    if file:
        iv = base64.b64decode(file.iv)
        cipher = AES.new(os.urandom(16), AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(file.file_data), AES.block_size)
        
        return send_from_directory(
            directory=os.getcwd(),
            filename=filename,
            as_attachment=True,
            mimetype='application/octet-stream'
        )
    return jsonify({'message': 'File not found'}), 404

if __name__ == '__main__':
    db.create_all()
    app.run(ssl_context='adhoc')  # This line ensures HTTPS is enabled
