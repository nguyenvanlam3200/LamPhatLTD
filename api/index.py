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

# Load environment variables
load_dotenv()

app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase connection
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

if not supabase_url or not supabase_key:
    raise Exception("Missing Supabase credentials")

supabase = create_client(supabase_url, supabase_key)


# Models
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
    image_url: str = ""
    stock: int
    specs: Optional[str] = ""


class Article(BaseModel):
    title: str
    content: str
    author: str
    image_url: Optional[str] = ""


class UserRegister(BaseModel):
    email: str
    name: str
    role: str = "customer"


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


# Root endpoint
@app.get("/")
def root():
    return {"message": "API is running", "status": "ok"}


# Test endpoint
@app.get("/api/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# Auth endpoints
@app.post("/api/auth/login")
async def login(user_login: UserLogin):
    try:
        users = supabase.table("users").select("*").eq("username", user_login.username).execute()

        if not users.data:
            raise HTTPException(status_code=401, detail="Sai tên đăng nhập hoặc mật khẩu")

        user = users.data[0]
        if verify_password(user_login.password, user["password"]):
            token = create_session_token(user["id"])
            return {
                "success": True,
                "token": token,
                "user": {
                    "id": user["id"],
                    "name": user["name"],
                    "role": user["role"],
                    "email": user["email"],
                    "username": user["username"]
                }
            }

        raise HTTPException(status_code=401, detail="Sai tên đăng nhập hoặc mật khẩu")
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/auth/logout")
async def logout(request: Request):
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token:
            supabase.table("sessions").delete().eq("token", token).execute()
        return {"success": True}
    except Exception as e:
        print(f"Logout error: {e}")
        return {"success": True}


@app.post("/api/auth/change-password")
async def change_password(data: ChangePassword):
    try:
        users = supabase.table("users").select("*").eq("username", data.username).execute()

        if not users.data:
            raise HTTPException(status_code=404, detail="Không tìm thấy user")

        user = users.data[0]
        if not verify_password(data.old_password, user["password"]):
            raise HTTPException(status_code=401, detail="Mật khẩu cũ không đúng")

        supabase.table("users").update({"password": hash_password(data.new_password)}).eq("username",
                                                                                          data.username).execute()
        return {"success": True, "message": "Đổi mật khẩu thành công"}
    except Exception as e:
        print(f"Change password error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# User management endpoints
@app.get("/api/users")
async def get_users():
    try:
        result = supabase.table("users").select("id, name, email, role, username, created_at").order("created_at",
                                                                                                     desc=True).execute()
        return {"users": result.data}
    except Exception as e:
        print(f"Get users error: {e}")
        return {"users": []}


@app.post("/api/users")
async def create_user(user: UserRegister):
    try:
        existing = supabase.table("users").select("*").eq("email", user.email).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail="Email đã tồn tại")

        default_password = hash_password("123456")
        username = user.email.split("@")[0]

        # Kiểm tra username đã tồn tại
        username_check = supabase.table("users").select("*").eq("username", username).execute()
        if username_check.data:
            username = f"{username}{secrets.token_hex(3)}"

        new_user = supabase.table("users").insert({
            "email": user.email,
            "name": user.name,
            "username": username,
            "password": default_password,
            "role": user.role
        }).execute()

        return {"success": True, "user": new_user.data[0]}
    except Exception as e:
        print(f"Create user error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str):
    try:
        supabase.table("sessions").delete().eq("user_id", user_id).execute()
        supabase.table("users").delete().eq("id", user_id).execute()
        return {"success": True, "message": "Đã xóa user"}
    except Exception as e:
        print(f"Delete user error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Products endpoints
@app.get("/api/products")
async def get_products():
    try:
        result = supabase.table("products").select("*").order("created_at", desc=True).execute()
        return {"products": result.data}
    except Exception as e:
        print(f"Get products error: {e}")
        return {"products": []}


@app.post("/api/products")
async def create_product(product: Product):
    try:
        new_product = supabase.table("products").insert({
            "name": product.name,
            "price": product.price,
            "description": product.description,
            "image_url": product.image_url,
            "stock": product.stock,
            "specs": product.specs
        }).execute()
        return {"success": True, "product": new_product.data[0]}
    except Exception as e:
        print(f"Create product error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/products/{product_id}")
async def delete_product(product_id: str):
    try:
        supabase.table("products").delete().eq("id", product_id).execute()
        return {"success": True}
    except Exception as e:
        print(f"Delete product error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Articles endpoints
@app.get("/api/articles")
async def get_articles():
    try:
        result = supabase.table("articles").select("*").order("created_at", desc=True).execute()
        return {"articles": result.data}
    except Exception as e:
        print(f"Get articles error: {e}")
        return {"articles": []}


@app.post("/api/articles")
async def create_article(article: Article):
    try:
        new_article = supabase.table("articles").insert({
            "title": article.title,
            "content": article.content,
            "author": article.author,
            "image_url": article.image_url
        }).execute()
        return {"success": True, "article": new_article.data[0]}
    except Exception as e:
        print(f"Create article error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/articles/{article_id}")
async def delete_article(article_id: str):
    try:
        supabase.table("articles").delete().eq("id", article_id).execute()
        return {"success": True}
    except Exception as e:
        print(f"Delete article error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Orders endpoints
@app.post("/api/orders")
async def create_order(order: Order):
    try:
        # Check stock
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

        # Reduce stock
        if product.data:
            supabase.table("products").update({"stock": product.data[0]["stock"] - order.quantity}).eq("id",
                                                                                                       order.product_id).execute()

        return {"success": True, "order": new_order.data[0]}
    except Exception as e:
        print(f"Create order error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Initialize default data
@app.on_event("startup")
def init_default_data():
    try:
        # Create admin user if not exists
        admin = supabase.table("users").select("*").eq("username", "admin").execute()
        if not admin.data:
            supabase.table("users").insert({
                "email": "admin@3dshop.com",
                "name": "Administrator",
                "username": "admin",
                "password": hash_password("admin"),
                "role": "admin"
            }).execute()
            print("✅ Created default admin user")

        # Create sample products if none exist
        products = supabase.table("products").select("*").limit(1).execute()
        if not products.data:
            sample_products = [
                {
                    "name": "Ender 3 V3 SE",
                    "price": 5990000,
                    "description": "Máy in 3D Ender 3 V3 SE - Công nghệ in nhanh, độ chính xác cao",
                    "image_url": "https://images.unsplash.com/photo-1581091226033-d5c48150dbaa?w=300",
                    "stock": 10,
                    "specs": "Công nghệ: FDM, Kích thước: 220x220x250mm"
                },
                {
                    "name": "Creality K1",
                    "price": 15990000,
                    "description": "Máy in 3D tốc độ cao 600mm/s, in tự động",
                    "image_url": "https://images.unsplash.com/photo-1581092335871-4a2c5b2b5b5b?w=300",
                    "stock": 5,
                    "specs": "Tốc độ: 600mm/s, AI camera"
                }
            ]
            for product in sample_products:
                supabase.table("products").insert(product).execute()
            print("✅ Created sample products")
    except Exception as e:
        print(f"Init data error: {e}")


# Vercel requires this
app_handler = app