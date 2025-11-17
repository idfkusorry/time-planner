# Установка и настройка планировщика задач

## Предварительные требования

- Python 3.8+
- PostgreSQL
- pip

## Шаги установки

1. **Клонируйте репозиторий**

   ```bash
   git clone https://github.com/idfkusorry/time-planner.git
   cd time_planner

2. **Создайте виртуальное окружение**

bash
python -m venv venv
# Для Windows:
venv\Scripts\activate
# Для Linux/Mac:
source venv/bin/activate

3. **Установите зависимости**

bash
pip install -r requirements.txt
Настройте базу данных

4. **Убедитесь, что PostgreSQL запущен**

Создайте базу данных:

sql
CREATE DATABASE planner_db;

5. **Настройте переменные окружения**

Скопируйте файл .env.example в .env

Отредактируйте .env файл с вашими настройками

6. **Запустите приложение**

bash
python app.py

7. **Откройте в браузере**

http://localhost:5000

## Создаем пример файла .env 

Создайте файл `.env.example`:

```env
# Database configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=planner_db
DB_USER=your_username
DB_PASSWORD=your_password

# Flask configuration
SECRET_KEY=your-super-secret-key-change-this-in-production
FLASK_ENV=development
FLASK_DEBUG=True

# JWT configuration
JWT_EXPIRATION_HOURS=24