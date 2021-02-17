import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, render_template, jsonify
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from dotenv import load_dotenv
from models import db, User

load_dotenv()

app = Flask(__name__)
app.config['DEBUG'] = os.getenv('DEBUG')
app.config['ENV'] = os.getenv('ENV')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

db.init_app(app)
jwt = JWTManager(app)
Migrate(app, db)
CORS(app)
manager = Manager(app)
manager.add_command('db', MigrateCommand)

@app.route('/')
def main():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username: return jsonify({"msg": "username is required"}), 400
    if not password: return jsonify({"msg": "password is required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user: return jsonify({"msg": "username/password are incorrect!!"}), 400

    if check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        data = {
            "access_token": access_token,
            "user": user.serialize()
        }

        return jsonify(data), 200
    else:
        return jsonify({"msg": "Register failed"}), 400

@app.route('/api/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username: return jsonify({"msg": "username is required"}), 400
    if not password: return jsonify({"msg": "password is required"}), 400

    user = User.query.filter_by(username=username).first()
    if user: return jsonify({"msg": "username already exists"}), 400

    user = User()
    user.username = username
    user.password = generate_password_hash(password)
    user.save()

    if user:
        access_token = create_access_token(identity=user.id)
        data = {
            "access_token": access_token,
            "user": user.serialize()
        }

        return jsonify(data), 200
    else:
        return jsonify({"msg": "Register failed"}), 400

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def profile():
    id = get_jwt_identity()
    user = User.query.get(id)
    return jsonify(user.serialize()), 200

if __name__ == '__main__':
    manager.run()
