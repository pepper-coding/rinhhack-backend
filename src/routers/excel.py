from fastapi import APIRouter, UploadFile, HTTPException
import io
import hashlib
from openpyxl import load_workbook

router = APIRouter()

file_buffer = None
file_hash = None


def calculate_file_hash(file_data: bytes) -> str:
    """
    Вычислить хэш для данных файла.
    """
    return hashlib.sha256(file_data).hexdigest()


@router.post("/upload_excel/")
async def upload_excel(file: UploadFile):
    """
    Эндпоинт для загрузки Excel-файла. Сохраняет файл в памяти, если он изменился.
    """
    global file_buffer, file_hash

    file_content = await file.read()
    new_hash = calculate_file_hash(file_content)

    if new_hash != file_hash:
        file_buffer = io.BytesIO(file_content)
        file_hash = new_hash
        return {"message": "File updated successfully!"}
    else:
        return {"message": "File has not changed."}


@router.get("/read_excel/")
def read_excel():
    """
    Эндпоинт для чтения Excel-файла из памяти.
    """
    if file_buffer is None:
        raise HTTPException(status_code=404, detail="No file uploaded.")

    file_buffer.seek(0)

    workbook = load_workbook(file_buffer)
    sheet = workbook.active

    # Читаем данные из первой строки
    data = [cell.value for cell in sheet[1]]

    return {"data": data}
