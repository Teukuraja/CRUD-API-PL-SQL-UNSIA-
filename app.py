from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from flask_migrate import Migrate
from Crypto.Util.Padding import pad, unpad
import base64
import os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://tugas_sql:12345@localhost/Tugas_SQL'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db) 
# Kunci enkripsi AES
SECRET_KEY = b'secretkey1234567'  # Ganti dengan kunci yang aman untuk produksi
cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=b'1234567890123456')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

# Fungsi enkripsi dan dekripsi menggunakan AES
encrypt_cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=b'1234567890123456')
decrypt_cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=b'1234567890123456')

# Fungsi enkripsi dan dekripsi menggunakan AES
def encrypt(text):
    ct_bytes = encrypt_cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

def decrypt(text):
    ct = base64.b64decode(text)
    pt = unpad(decrypt_cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# Endpoint CRUD untuk User

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    new_user = User(username=data['username'], password=encrypt(data['password']))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    decrypted_password = decrypt(user.password)
    return jsonify({'id': user.id, 'username': user.username, 'password': decrypted_password})

@app.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    user_list = []

    for user in users:
        decrypted_password = decrypt(user.password)
        user_data = {'id': user.id, 'username': user.username, 'password': decrypted_password}
        user_list.append(user_data)

    return jsonify({'users': user_list})


@app.route('/user/<user_id>', methods=['PUT'])
def update_user(user_id):
    user = User.query.get(user_id)
    data = request.get_json()
    user.username = data['username']
    user.password = encrypt(data['password'])
    db.session.commit()
    return jsonify({'message': 'User updated successfully'})

@app.route('/user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
