# sample-api/main.py

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Sample E-commerce API")

# In-memory database
users = {
    1: {"id": 1, "name": "Alice", "email": "alice@email.com", "role": "user"},
    2: {"id": 2, "name": "Bob", "email": "bob@email.com", "role": "admin"}
}

products = {
    1: {"id": 1, "name": "Laptop", "price": 999.99},
    2: {"id": 2, "name": "Mouse", "price": 29.99}
}

orders = {
    1: {"id": 1, "user_id": 1, "product_id": 1, "quantity": 1},
    2: {"id": 2, "user_id": 2, "product_id": 2, "quantity": 5}
}

# Models
class User(BaseModel):
    id: int
    name: str
    email: str
    role: str

class Product(BaseModel):
    id: int
    name: str
    price: float

class Order(BaseModel):
    id: int
    user_id: int
    product_id: int
    quantity: int

# Endpoints
@app.get("/")
def root():
    return {"message": "Sample E-commerce API"}

@app.get("/users", response_model=List[User])
def get_users():
    return list(users.values())

@app.get("/users/{user_id}", response_model=User)
def get_user(user_id: int):
    # INTENTIONAL VULNERABILITY: No auth check (BOLA)
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    return users[user_id]

@app.post("/users", response_model=User)
def create_user(user: User):
    if user.id in users:
        raise HTTPException(status_code=400, detail="User already exists")
    users[user.id] = user.dict()
    return user

@app.get("/products", response_model=List[Product])
def get_products():
    return list(products.values())

@app.get("/users/{user_id}/orders", response_model=List[Order])
def get_user_orders(user_id: int):
    # INTENTIONAL VULNERABILITY: No auth check
    user_orders = [o for o in orders.values() if o["user_id"] == user_id]
    return user_orders

@app.post("/search")
def search_products(query: str):
    # INTENTIONAL VULNERABILITY: SQL injection possible (simulated)
    # In real scenario, this would use SQL directly
    results = [p for p in products.values() if query.lower() in p["name"].lower()]
    return results

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)