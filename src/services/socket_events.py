import socketio

sio = socketio.AsyncServer()

@sio.on("connect")
async def connect(sid, environ):
    print(f"Client {sid} connected.")

@sio.on("edit_cell")
async def edit_cell(sid, data):
    print(f"Received data from {sid}: {data}")
    await sio.emit("cell_updated", data)

@sio.on("disconnect")
async def disconnect(sid):
    print(f"Client {sid} disconnected.")
