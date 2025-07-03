from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from typing import Optional
import secrets

app = FastAPI(
    title="Fujitsu Coding Test API",
    description="API for managing users and their access to resources.",
)

security = HTTPBasic()

users_db = {
    "testuser": {
        "password_hass": "hashed_password_for_testuser",
        "nickname": "Test User",
        "comment": "This is a test user.",
    },
    "TaroYamada": {
        "password_hass": "hashed_password_for_TaroYamada",
        "nickname": "Taro Yamada",
        "comment": "元気です！",
    },
}

class SignupRequest(BaseModel):
    user_id: str = Field(..., min_length=6, max_length=20, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(..., min_length=8, max_length=20, regex=r"^[!-~]+$")

class UserResponse(BaseModel):
    user_id: str
    nickname: str
    comment: Optional[str] = None

class UserUpdateRequest(BaseModel):
    nickname: Optional[str] = Field(None, max_length=30)
    comment: Optional[str] = Field(None, max_length=100)

    def check_at_least_one_field(self):
        if self.nickname is None and self.comment is None:
            raise ValueError("At least one field (nickname or comment) must be provided.")
        return self

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    current_user_id = credentials.username
    current_password = credentials.password

    if current_user_id not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    exceptd_password_hash_dummy = current_user_id[::-1]
    if current_password != exceptd_password_hash_dummy:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username

@app.post("/signup", summary="ユーザアカウントの作成")
async def signup(request: SignupRequest):
    if request.user_id in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Account creation failed", "cause": "Already same user_id is used."},
        )
    
    hashed_password_dummy = request.user_id[::-1]
    
    users_db[request.user_id] = {
        "password_hass": hashed_password_dummy,
        "nickname": request.user_id,
        "comment": None,
    }
    return {"message": "Account successfully created.",
            "user": {
                "user_id": request.user_id,
                "nickname": request.user_id,
            }}

@app.get("/users/{userid}", response_model=UserResponse)
async def get_user_info(user_id: str, authenticated_user: str = Depends(authenticate_user)):
    user_data = users_db.get(user_id)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    return UserResponse(
        user_id=user_id,
        nickname=user_data["nickname"],
        comment=user_data.get("comment"),
    )

@app.patch("/users/{userid}", response_model=UserResponse, summary="ユーザ情報の更新")
async def update_user_info(
    user_id: str,
    update_request: UserUpdateRequest,
    authenticated_user: str = Depends(authenticate_user)
):
    if user_id != authenticated_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": "No permission for update"},
        )
    
    if user_id not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "No User found"},
        )
    
    try:
        request.check_at_least_one_field()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Update failed", "cause": str(e)},
        )
    
    current_user_data = users_db[user_id]

    if request.nickname is not None:
        if not (1 <= len(request.nickname) <= 30):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "User update failed", "cause": "Invalid nickname length."},
            )
        current_user_data["nickname"] = request.nickname
    
    if request.comment is not None:
        if not (0 <= len(request.comment) <= 100):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "User update failed", "cause": "Invalid comment length."},
            )
        current_user_data["comment"] = request.comment
    
    users_db[user_id] = current_user_data

    return {
        "message": "User successfully updated.",
        "user": {
            "user_id": user_id,
            "nickname": current_user_data["nickname"],
            "comment": current_user_data.get("comment"),
        }
    }

@app.post("/close", summary="アカウントの削除")
async def close_account(authenticated_user: str = Depends(authenticate_user)):
    if authenticated_user not in users_db:
        del users_db[authenticated_user]
        return {"message": "Account and user successfully removed."}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "No user found to remove."},
        )

if __name__ == "__main__":
    import uvicorn
    import os
    
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)