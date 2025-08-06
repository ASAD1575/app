from passlib.context import CryptContext
import shutil
from docx2pdf import convert
import os
import uuid

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def convert_word_to_pdf(upload_path: str, output_dir: str) -> str:
    pdf_filename = f"{uuid.uuid4()}.pdf"
    output_path = os.path.join(output_dir, pdf_filename)
    convert(upload_path, output_path)
    return output_path
