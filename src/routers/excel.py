from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from services.excel_service import generate_excel_file

router = APIRouter()

@router.get("/download", response_class=FileResponse, summary="Скачать Excel файл", description="Генерация и скачивание Excel файла с данными.")
async def download_excel():
    file_path = generate_excel_file()
    if not file_path:
        raise HTTPException(status_code=500, detail="Could not generate Excel file")
    return FileResponse(file_path, filename="data.xlsx")
