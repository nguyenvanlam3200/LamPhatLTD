from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# Cho phép frontend gọi API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Kết nối Supabase
supabase = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)

# Model dữ liệu
class User(BaseModel):
    name: str
    email: str

# API lấy danh sách users
@app.get("/api/users")
def get_users():
    result = supabase.table("users").select("*").order("created_at", desc=True).execute()
    return {"users": result.data}

# API thêm user mới
@app.post("/api/users")
def create_user(user: User):
    try:
        result = supabase.table("users").insert({
            "name": user.name,
            "email": user.email
        }).execute()
        return {"message": "Thêm thành công!", "user": result.data[0]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# API xóa user
@app.delete("/api/users/{user_id}")
def delete_user(user_id: str):
    supabase.table("users").delete().eq("id", user_id).execute()
    return {"message": "Đã xóa!"}