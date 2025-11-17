from flask import Blueprint, request, jsonify, render_template, redirect, url_for
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
import re

auth_bp = Blueprint('auth', __name__)

# Имитация базы данных пользователей
users_db = {}
user_id_counter = 1

def validate_email(email):
    """Проверка валидности email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def make_auth_request(endpoint, data):
    """Имитация запроса к серверу аутентификации"""
    if endpoint == 'register':
        return register_user(data)
    elif endpoint == 'login':
        return login_user(data)
    return None

def register_user(data):
    """Регистрация пользователя"""
    global user_id_counter
    
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    
    # Валидация email
    if not validate_email(email):
        return {'error': 'Invalid email format'}, 400
    
    # Проверка, что email или username не заняты
    for user_data in users_db.values():
        if user_data['email'] == email:
            return {'error': 'Email already exists'}, 400
        if user_data['username'] == username:
            return {'error': 'Username already exists'}, 400
    
    # Хэшируем пароль
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    user_id = user_id_counter
    users_db[user_id] = {
        'email': email,
        'username': username,
        'password': hashed_password,
        'user_id': user_id
    }
    user_id_counter += 1
    
    # Создаем токены
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user_id': user_id,
        'username': username,
        'email': email
    }, 201

def login_user(data):
    """Аутентификация пользователя"""
    login = data.get('login')  # Может быть email или username
    password = data.get('password')
    
    # Ищем пользователя по email или username
    user = None
    for user_data in users_db.values():
        if user_data['email'] == login or user_data['username'] == login:
            user = user_data
            break
    
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return {'error': 'Invalid credentials'}, 401
    
    # Создаем токены
    access_token = create_access_token(user['user_id'])
    refresh_token = create_refresh_token(user['user_id'])
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user_id': user['user_id'],
        'username': user['username'],
        'email': user['email']
    }, 200

def create_access_token(user_id):
    """Создание access token"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow(),
        'type': 'access'
    }
    return jwt.encode(payload, 'your-secret-key-here', algorithm='HS256')

def create_refresh_token(user_id):
    """Создание refresh token"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30),
        'iat': datetime.utcnow(),
        'type': 'refresh'
    }
    return jwt.encode(payload, 'your-secret-key-here', algorithm='HS256')

def token_required(f):
    """Декоратор для проверки JWT токена"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Проверяем формат заголовка
            parts = auth_header.split()
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'error': 'Invalid token format'}), 401
            
            token = parts[1]
            payload = jwt.decode(token, 'your-secret-key-here', algorithms=['HS256'])
            
            if payload['type'] != 'access':
                return jsonify({'error': 'Invalid token type'}), 401
            
            # Проверяем, что пользователь существует
            user_id = payload['user_id']
            if user_id not in users_db:
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'Invalid token: {str(e)}'}), 401
        except Exception as e:
            return jsonify({'error': f'Token validation error: {str(e)}'}), 401
        
        return f(*args, **kwargs)
    return decorated

@auth_bp.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    result, status_code = make_auth_request('login', data)
    return jsonify(result), status_code

@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    result, status_code = make_auth_request('register', data)
    return jsonify(result), status_code