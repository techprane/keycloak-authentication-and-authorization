import json
from typing import Dict, List

import httpx
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import jwt, jwk
from jose.exceptions import JWTError
from pydantic import BaseModel

# Configuration
KEYCLOAK_URL = "http://localhost:8080"
REALM_NAME = "fastapi-realm"
KEYCLOAK_CLIENT_ID = "fastapi-client"

# JWKs URL
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"

# OAuth2 scheme
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/auth",
    tokenUrl=f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token",
    auto_error=False
)

# FastAPI app
app = FastAPI()


# Models
class TokenData(BaseModel):
    username: str
    roles: List[str]
    
# Item model
class Item(BaseModel):
    name: str
    description: str
    price: float


# Token validation function
async def validate_token(token: str) -> TokenData:
    try:
        # Fetch JWKS
        async with httpx.AsyncClient() as client:
            response = await client.get(JWKS_URL)
            response.raise_for_status()
            jwks = response.json()

        # Decode the token headers to get the key ID (kid)
        headers = jwt.get_unverified_headers(token)
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token missing 'kid' header")

        # Find the correct key in the JWKS
        key_data = next((key for key in jwks["keys"] if key["kid"] == kid), None)
        if not key_data:
            raise HTTPException(status_code=401, detail="Matching key not found in JWKS")

        # Convert JWK to RSA public key
        public_key = jwk.construct(key_data).public_key()

        # Verify the token
        payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            audience=KEYCLOAK_CLIENT_ID
        )

        # Extract username and roles
        username = payload.get("preferred_username")
        roles = payload.get("realm_access", {}).get("roles", [])
        if not username or not roles:
            raise HTTPException(status_code=401, detail="Token missing required claims")

        return TokenData(username=username, roles=roles)

    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

# Dependency to get the current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return await validate_token(token)

# Role-Based Access Control (RBAC)
def has_role(required_role: str):
    def role_checker(token_data: TokenData = Depends(get_current_user)) -> TokenData:
        if required_role not in token_data.roles:
            raise HTTPException(status_code=403, detail="Not authorized")
        return token_data
    return role_checker

# Routes
@app.get("/public")
async def public_endpoint():
    return {"message": "This is a public endpoint accessible to everyone."}

@app.get("/protected")
async def protected_endpoint(current_user: TokenData = Depends(get_current_user)):
    return {
        "message": f"Hello {current_user.username}, you are authenticated!",
        "roles": current_user.roles,
    }

# In-memory database for demo purposes
items_db = {}

# Create an item (Admin only)
@app.post("/admin/items", dependencies=[Depends(has_role("admin"))])
async def create_item(item: Item):
    if item.name in items_db:
        raise HTTPException(status_code=400, detail="Item already exists")
    items_db[item.name] = item
    return {"message": f"Item '{item.name}' created successfully", "item": item}

# Read all items (Admin only)
@app.get("/admin/items", dependencies=[Depends(has_role("admin"))])
async def get_all_items():
    return {"items": list(items_db.values())}

# Read a single item by name (Admin only)
@app.get("/admin/items/{item_name}", dependencies=[Depends(has_role("admin"))])
async def get_item(item_name: str):
    item = items_db.get(item_name)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

# Update an item by name (Admin only)
@app.put("/admin/items/{item_name}", dependencies=[Depends(has_role("admin"))])
async def update_item(item_name: str, updated_item: Item):
    if item_name not in items_db:
        raise HTTPException(status_code=404, detail="Item not found")
    items_db[item_name] = updated_item
    return {"message": f"Item '{item_name}' updated successfully", "item": updated_item}

# Delete an item by name (Admin only)
@app.delete("/admin/items/{item_name}", dependencies=[Depends(has_role("admin"))])
async def delete_item(item_name: str):
    if item_name not in items_db:
        raise HTTPException(status_code=404, detail="Item not found")
    del items_db[item_name]
    return {"message": f"Item '{item_name}' deleted successfully"}
# @app.get("/admin")
# async def admin_endpoint(current_user: TokenData = Depends(has_role("admin"))):
#     return {
#         "message": f"Hello {current_user.username}, you have admin access!"
#     }

@app.get("/developer", dependencies=[Depends(has_role("developer"))])
async def developer_endpoint():
    return {"items":list(items_db.values())}


# async def developer_endpoint(current_user: TokenData = Depends(has_role("developer"))):
#     return {
#         "message": f"Hello {current_user.username}, you have developer read-only access!"
#     }
