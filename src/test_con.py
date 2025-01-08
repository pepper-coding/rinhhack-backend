import socketio
import openpyxl
import base64
from io import BytesIO

# Адрес сервера
SERVER_URL = 'http://localhost:8000'

# Создаем клиент для Socket.IO
sio = socketio.Client()

# Событие, которое срабатывает при подключении
@sio.event
def connect():
    print("Подключено к серверу")
    # Запрашиваем файл с сервера
    sio.emit('get_file')

# Событие, которое срабатывает при получении файла
@sio.event
def file_update(data):
    print("Файл получен от сервера")

    # Декодируем файл из base64
    file_content = base64.b64decode(data['data'])

    # Открываем файл Excel из байтов
    with BytesIO(file_content) as file_stream:
        wb = openpyxl.load_workbook(file_stream)
        sheet = wb.active

        # Изменяем одну ячейку (например, A1)
        sheet['A1'] = "я гандон"

        # Сохраняем изменения в файл Excel
        with BytesIO() as modified_stream:
            wb.save(modified_stream)
            modified_stream.seek(0)
            modified_content = modified_stream.read()

        # Отправляем измененный файл на сервер
        encoded_content = base64.b64encode(modified_content).decode('utf-8')
        sio.emit('upload_file', {'data': encoded_content, 'filename': 'test.xlsx'})

# Событие, которое срабатывает при отключении
@sio.event
def disconnect():
    print("Отключено от сервера")

# Подключаемся к серверу
sio.connect(SERVER_URL)

# Ожидаем завершения работы клиента
sio.wait()
