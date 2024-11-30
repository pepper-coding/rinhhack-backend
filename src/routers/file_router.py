import socketio
import base64


sio = socketio.Client()

@sio.event
def connect():
    print("Successfully connected to the server!")
    sio.emit('get_file')

@sio.event
def file_update(data):
    file_content = base64.b64decode(data['data'])
    with open("received_file.xlsx", "wb") as f:
        f.write(file_content)
    print("File received and saved.")
@sio.event
def error(data):
    print(f"Error: {data['message']}")

@sio.event
def disconnect():
    print("Disconnected from the server.")

sio.connect('http://localhost:8000')

sio.wait()
