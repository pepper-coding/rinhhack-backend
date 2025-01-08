import socketio
import openpyxl
import base64
import io
import requests

# Адрес вашего сервера FastAPI
SERVER_URL = "http://127.0.0.1:8000"

# JWT токен для авторизации (предполагаем, что он уже есть)
JWT_TOKEN = "your_jwt_token_here"

# Подключение через WebSocket
sio = socketio.Client()

# Функция для получения файла через WebSocket
def request_file():
    print("Запрос файла на сервер...")
    sio.emit('get_file')  # Запрашиваем файл от сервера

# Функция для обработки получения файла
@sio.event
def file_update(data):
    print("Получен файл от сервера.")
    if 'data' in data:
        file_data = base64.b64decode(data['data'])
        file = io.BytesIO(file_data)
        wb = openpyxl.load_workbook(file)

        # Пример редактирования: Изменим первое значение в первой ячейке на "Hello"
        sheet = wb.active
        sheet['A1'] = "Hello"

        # Сохраняем изменения в файл
        modified_file = io.BytesIO()
        wb.save(modified_file)
        modified_file.seek(0)

        # Отправляем изменённый файл обратно на сервер
        send_modified_file(modified_file)
    else:
        print("Ошибка: данные не получены корректно.")

# Функция для отправки изменённого файла на сервер
def send_modified_file(file_data):
    files = {
        'file': ('modified_file.xlsx', file_data, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    }

    headers = {
        'Authorization': f'Bearer {JWT_TOKEN}'
    }

    print("Отправка изменённого файла на сервер...")
    # Отправляем файл на сервер
    response = requests.post(f"{SERVER_URL}/excel/upload", files=files, headers=headers)

    if response.status_code == 200:
        print("Файл успешно загружен на сервер!")
    else:
        print(f"Ошибка загрузки файла: {response.status_code} - {response.text}")

# Подключение к серверу
def connect_to_server():
    try:
        print("Подключение к серверу...")
        sio.connect(SERVER_URL)

        # Запрашиваем файл после подключения
        request_file()
    except Exception as e:
        print(f"Ошибка подключения: {e}")

# Обработчик ошибок
@sio.event
def connect_error(data):
    print(f"Не удалось подключиться к серверу: {data}")

# Обработчик отключения
@sio.event
def disconnect():
    print("Отключено от сервера.")

# Главная функция клиента
if __name__ == '__main__':
    try:
        connect_to_server()
    except KeyboardInterrupt:
        print("Завершение работы клиента.")
        sio.disconnect()
