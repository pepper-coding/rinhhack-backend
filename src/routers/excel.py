from fastapi import APIRouter, UploadFile, HTTPException
import io
import hashlib
from openpyxl import load_workbook

router = APIRouter()

file_buffer = None
file_hash = None
