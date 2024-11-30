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
