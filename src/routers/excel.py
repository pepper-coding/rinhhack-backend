from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from services.excel_service import generate_excel_file

router = APIRouter()

@router.get("/download/excel")
async def download_excel():
    file_path = generate_excel_file()
    if not file_path:
        raise HTTPException(status_code=500, detail="Could not generate Excel file")
    return FileResponse(file_path, filename="data.xlsx")
