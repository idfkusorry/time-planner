from flask import Flask, render_template, request, jsonify, redirect, url_for
from datetime import datetime, timedelta, date
import jwt
import re
from functools import wraps
import os
from dotenv import load_dotenv
from models import db, User, Task

# Загружаем переменные окружения
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_EXPIRATION_DELTA'] = timedelta(hours=int(os.getenv('JWT_EXPIRATION_HOURS', 24)))

db.init_app(app)

def validate_email(email):
    """Проверка валидности email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def create_token(user_id):
    """Создание JWT токена"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    """Декоратор для проверки JWT токена"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            parts = auth_header.split()
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'error': 'Invalid token format'}), 401
            
            token = parts[1]
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            
            # Проверяем, что пользователь существует в БД
            user_id = payload['user_id']
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'Invalid token: {str(e)}'}), 401
        
        return f(*args, **kwargs)
    return decorated

def get_user_id_from_token():
    """Извлекает user_id из JWT токена"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None
    
    try:
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload.get('user_id')
    except:
        return None

# Маршруты
@app.route('/')
def index():
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/tasks')
def tasks_page():
    return render_template('tasks.html')

@app.route('/create-task')
def create_task_page():
    return render_template('create_task.html')

@app.route('/api/verify-token')
def verify_token():
    """Проверка валидности токена"""
    try:
        user_id = get_user_id_from_token()
        if user_id:
            user = User.query.get(user_id)
            if user:
                return jsonify({'valid': True, 'user_id': user_id})
        return jsonify({'valid': False}), 401
    except:
        return jsonify({'valid': False}), 401

# API endpoints
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        
        # Валидация
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Проверка существования пользователя
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        # Создание пользователя
        user = User(email=email, username=username)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Создание токена
        token = create_token(user.id)
        
        return jsonify({
            'message': 'User created successfully',
            'access_token': token,
            'user_id': user.id,
            'username': user.username,
            'email': user.email
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        login_input = data.get('login')
        password = data.get('password')
        
        # Поиск пользователя по email или username
        user = User.query.filter(
            (User.email == login_input) | (User.username == login_input)
        ).first()
        
        if user and user.check_password(password):
            # Создание токена
            token = create_token(user.id)
            
            return jsonify({
                'message': 'Login successful',
                'access_token': token,
                'user_id': user.id,
                'username': user.username,
                'email': user.email
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tasks', methods=['GET'])
@token_required
def get_tasks():
    try:
        user_id = get_user_id_from_token()
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
        
        sort_by = request.args.get('sort', 'created_at')
        tasks = Task.query.filter_by(user_id=user_id)
        
        if sort_by == 'due_date':
            tasks = tasks.order_by(Task.due_date.asc())
        else:
            tasks = tasks.order_by(Task.created_at.desc())
            
        return jsonify([task.to_dict() for task in tasks.all()])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tasks', methods=['POST'])
@token_required
def create_task():
    try:
        user_id = get_user_id_from_token()
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
        
        data = request.get_json()
        
        # Валидация
        if not data.get('title'):
            return jsonify({'error': 'Title is required'}), 400
        if not data.get('due_date'):
            return jsonify({'error': 'Due date is required'}), 400
        
        # Преобразуем дату
        due_date = datetime.strptime(data['due_date'], '%Y-%m-%d').date()
        
        # Проверяем, что пользователь существует
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        task = Task(
            title=data['title'],
            description=data.get('description', ''),
            due_date=due_date,
            user_id=user_id
        )
        
        db.session.add(task)
        db.session.commit()
        
        return jsonify(task.to_dict()), 201
        
    except ValueError as e:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(task_id):
    try:
        user_id = get_user_id_from_token()
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
        
        # Находим задачу конкретного пользователя
        task = Task.query.filter_by(id=task_id, user_id=user_id).first()
        if not task:
            return jsonify({'error': 'Task not found'}), 404            
        
        data = request.get_json()
        
        if 'title' in data:
            task.title = data['title']
        if 'description' in data:
            task.description = data['description']
        if 'due_date' in data:
            task.due_date = datetime.strptime(data['due_date'], '%Y-%m-%d').date()
        if 'completed' in data:
            task.completed = data['completed']
            
        db.session.commit()
        return jsonify(task.to_dict())
        
    except ValueError as e:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(task_id):
    try:
        user_id = get_user_id_from_token()
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
        
        # Находим задачу конкретного пользователя
        task = Task.query.filter_by(id=task_id, user_id=user_id).first()
        if not task:
            return jsonify({'error': 'Task not found'}), 404
            
        db.session.delete(task)
        db.session.commit()
        
        return jsonify({'message': 'Task deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/upcoming-tasks')
@token_required
def get_upcoming_tasks():
    try:
        user_id = get_user_id_from_token()
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
        
        today = date.today()
        tomorrow = today + timedelta(days=1)
        
        tasks = Task.query.filter(
            Task.user_id == user_id,
            Task.due_date.between(today, tomorrow),
            Task.completed == False
        ).all()
        
        return jsonify([task.to_dict() for task in tasks])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)