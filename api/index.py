from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import hashlib
import secrets
from typing import Optional

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

supabase = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)


# Models
class UserRegister(BaseModel):
    email: str
    name: str
    role: str = "customer"


class UserLogin(BaseModel):
    username: str
    password: str


class ChangePassword(BaseModel):
    username: str
    old_password: str
    new_password: str


class Product(BaseModel):
    name: str
    price: float
    description: str
    image_url: str
    stock: int
    specs: Optional[str] = ""


class Article(BaseModel):
    title: str
    content: str
    author: str
    image_url: Optional[str] = ""


class Order(BaseModel):
    user_id: str
    product_id: str
    quantity: int
    total_price: float


# Helper functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


def create_session_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    supabase.table("sessions").insert({
        "user_id": user_id,
        "token": token,
        "expires_at": (datetime.now() + timedelta(days=7)).isoformat()
    }).execute()
    return token


def get_user_from_token(token: str):
    result = supabase.table("sessions").select("user_id").eq("token", token).gte("expires_at",
                                                                                 datetime.now().isoformat()).execute()
    if result.data:
        user = supabase.table("users").select("*").eq("id", result.data[0]["user_id"]).execute()
        return user.data[0] if user.data else None
    return None


# ============= AUTH API =============
@app.post("/api/auth/login")
def login(user_login: UserLogin):
    users = supabase.table("users").select("*").eq("username", user_login.username).execute()

    if not users.data:
        raise HTTPException(status_code=401, detail="Sai tên đăng nhập hoặc mật khẩu")

    user = users.data[0]
    if verify_password(user_login.password, user["password"]):
        token = create_session_token(user["id"])
        return {"success": True, "token": token,
                "user": {"id": user["id"], "name": user["name"], "role": user["role"], "email": user["email"]}}

    raise HTTPException(status_code=401, detail="Sai tên đăng nhập hoặc mật khẩu")


@app.post("/api/auth/google")
def google_login(request: Request):
    data = request.json()
    email = data.get("email")
    name = data.get("name")

    users = supabase.table("users").select("*").eq("email", email).execute()

    if users.data:
        user = users.data[0]
        token = create_session_token(user["id"])
        return {"success": True, "token": token,
                "user": {"id": user["id"], "name": user["name"], "role": user["role"], "email": user["email"]}}
    else:
        # Tạo user mới với role customer
        new_user = supabase.table("users").insert({
            "email": email,
            "name": name,
            "username": email.split("@")[0],
            "password": hash_password(secrets.token_urlsafe(12)),
            "role": "customer"
        }).execute()

        if new_user.data:
            token = create_session_token(new_user.data[0]["id"])
            return {"success": True, "token": token,
                    "user": {"id": new_user.data[0]["id"], "name": name, "role": "customer", "email": email}}

    raise HTTPException(status_code=400, detail="Đăng nhập thất bại")


@app.post("/api/auth/logout")
def logout(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        supabase.table("sessions").delete().eq("token", token).execute()
    return {"success": True}


@app.post("/api/auth/change-password")
def change_password(data: ChangePassword):
    users = supabase.table("users").select("*").eq("username", data.username).execute()

    if not users.data:
        raise HTTPException(status_code=404, detail="Không tìm thấy user")

    user = users.data[0]
    if not verify_password(data.old_password, user["password"]):
        raise HTTPException(status_code=401, detail="Mật khẩu cũ không đúng")

    supabase.table("users").update({"password": hash_password(data.new_password)}).eq("username",
                                                                                      data.username).execute()
    return {"success": True, "message": "Đổi mật khẩu thành công"}


# ============= USER MANAGEMENT =============
@app.get("/api/users")
def get_users():
    result = supabase.table("users").select("id, name, email, role, username, created_at").order("created_at",
                                                                                                 desc=True).execute()
    return {"users": result.data}


@app.post("/api/users")
def create_user(user: UserRegister):
    existing = supabase.table("users").select("*").eq("email", user.email).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Email đã tồn tại")

    default_password = hash_password("123456")
    username = user.email.split("@")[0]

    new_user = supabase.table("users").insert({
        "email": user.email,
        "name": user.name,
        "username": username,
        "password": default_password,
        "role": user.role
    }).execute()

    return {"success": True, "user": new_user.data[0]}


@app.delete("/api/users/{user_id}")
def delete_user(user_id: str):
    supabase.table("sessions").delete().eq("user_id", user_id).execute()
    supabase.table("users").delete().eq("id", user_id).execute()
    return {"success": True, "message": "Đã xóa user"}


@app.put("/api/users/{user_id}/role")
def update_user_role(user_id: str, role: str):
    supabase.table("users").update({"role": role}).eq("id", user_id).execute()
    return {"success": True}


# ============= PRODUCTS API =============
@app.get("/api/products")
def get_products():
    result = supabase.table("products").select("*").order("created_at", desc=True).execute()
    return {"products": result.data}


@app.post("/api/products")
def create_product(product: Product):
    new_product = supabase.table("products").insert({
        "name": product.name,
        "price": product.price,
        "description": product.description,
        "image_url": product.image_url,
        "stock": product.stock,
        "specs": product.specs
    }).execute()
    return {"success": True, "product": new_product.data[0]}


@app.put("/api/products/{product_id}")
def update_product(product_id: str, product: Product):
    supabase.table("products").update({
        "name": product.name,
        "price": product.price,
        "description": product.description,
        "image_url": product.image_url,
        "stock": product.stock,
        "specs": product.specs
    }).eq("id", product_id).execute()
    return {"success": True}


@app.delete("/api/products/{product_id}")
def delete_product(product_id: str):
    supabase.table("products").delete().eq("id", product_id).execute()
    return {"success": True}


# ============= ARTICLES API =============
@app.get("/api/articles")
def get_articles():
    result = supabase.table("articles").select("*").order("created_at", desc=True).execute()
    return {"articles": result.data}


@app.post("/api/articles")
def create_article(article: Article):
    new_article = supabase.table("articles").insert({
        "title": article.title,
        "content": article.content,
        "author": article.author,
        "image_url": article.image_url
    }).execute()
    return {"success": True, "article": new_article.data[0]}


@app.put("/api/articles/{article_id}")
def update_article(article_id: str, article: Article):
    supabase.table("articles").update({
        "title": article.title,
        "content": article.content,
        "image_url": article.image_url
    }).eq("id", article_id).execute()
    return {"success": True}


@app.delete("/api/articles/{article_id}")
def delete_article(article_id: str):
    supabase.table("articles").delete().eq("id", article_id).execute()
    return {"success": True}


# ============= ORDERS API =============
@app.post("/api/orders")
def create_order(order: Order):
    # Kiểm tra stock
    product = supabase.table("products").select("stock").eq("id", order.product_id).execute()
    if product.data and product.data[0]["stock"] < order.quantity:
        raise HTTPException(status_code=400, detail="Sản phẩm không đủ số lượng")

    new_order = supabase.table("orders").insert({
        "user_id": order.user_id,
        "product_id": order.product_id,
        "quantity": order.quantity,
        "total_price": order.total_price,
        "status": "pending"
    }).execute()

    # Giảm stock
    supabase.table("products").update({"stock": product.data[0]["stock"] - order.quantity}).eq("id",
                                                                                               order.product_id).execute()

    return {"success": True, "order": new_order.data[0]}


@app.get("/api/orders/{user_id}")
def get_user_orders(user_id: str):
    result = supabase.table("orders").select("*, products(*)").eq("user_id", user_id).execute()
    return {"orders": result.data}


# Khởi tạo dữ liệu mặc định
@app.on_event("startup")
def init_default_data():
    # Tạo user admin nếu chưa có
    admin = supabase.table("users").select("*").eq("username", "admin").execute()
    if not admin.data:
        supabase.table("users").insert({
            "email": "admin@3dshop.com",
            "name": "Administrator",
            "username": "admin",
            "password": hash_password("admin"),
            "role": "admin"
        }).execute()