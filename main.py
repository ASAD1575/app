from fastapi import FastAPI, Request, Form, UploadFile, File, Query
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
# Assuming these functions exist in your database.py and handle user/token operations
from database import create_user, verify_user, get_user_by_email, get_user_by_username, update_user_password
import os
import subprocess
import uuid

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --- PDF conversion endpoint ---
@app.post("/convert")
async def convert_to_pdf(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    input_path = os.path.join(UPLOAD_DIR, file_id + ".docx")
    output_path = os.path.join(UPLOAD_DIR, file_id + ".pdf")

    with open(input_path, "wb") as f:
        f.write(await file.read())

    # Ensure libreoffice is installed and accessible in your environment
    try:
        subprocess.run(["libreoffice", "--headless", "--convert-to", "pdf", input_path, "--outdir", UPLOAD_DIR], check=True)
    except subprocess.CalledProcessError as e:
        print(f"LibreOffice conversion failed: {e}")
        return JSONResponse({"status": "failed", "message": "PDF conversion failed."}, status_code=500)
    except FileNotFoundError:
        print("LibreOffice command not found. Please ensure LibreOffice is installed and in your PATH.")
        return JSONResponse({"status": "failed", "message": "Server error: PDF converter not found."}, status_code=500)

    if os.path.exists(output_path):
        return JSONResponse({"status": "completed", "file_id": file_id})
    else:
        return JSONResponse({"status": "failed", "message": "PDF output file not found after conversion."}, status_code=500)


@app.get("/download/{file_id}")
async def download_pdf(file_id: str):
    pdf_path = os.path.join(UPLOAD_DIR, file_id + ".pdf")
    if os.path.exists(pdf_path):
        return FileResponse(pdf_path, filename="converted.pdf")
    return JSONResponse({"error": "File not found"}, status_code=404)

# --- Registration ---
@app.get("/register", response_class=HTMLResponse)
async def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register_user(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...)):
    if create_user(username, email, password): # Assumes create_user handles unique username/email
        return RedirectResponse("/login?message=registration_success", status_code=303)
    return templates.TemplateResponse("register.html", {"request": request, "error": "Username or Email already exists"})

# --- Login ---
@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    message = request.query_params.get("message")
    error = request.query_params.get("error")
    return templates.TemplateResponse("login.html", {"request": request, "message": message, "error": error})

@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if verify_user(username, password):
        return RedirectResponse(f"/dashboard?username={username}", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password"})

# --- Direct Password Reset ---
@app.get("/forgot_password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("forgot_password.html", {"request": request, "error": error})

@app.post("/reset_password_direct")
async def reset_password_direct(request: Request, username_or_email: str = Form(...), new_password: str = Form(...), confirm_new_password: str = Form(...)):
    if new_password != confirm_new_password:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Passwords do not match."})

    user = get_user_by_email(username_or_email)
    if not user:
        user = get_user_by_username(username_or_email)

    if user:
        if update_user_password(user["email"], new_password):
            return RedirectResponse("/login?message=password_reset_success", status_code=303)
        else:
            return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Failed to reset password. Please try again."})
    else:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "No account found with that username or email."})

# --- Root and dashboard ---
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, username: str = Query("Guest")):
    user = {"username": username}
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})
