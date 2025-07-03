from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from typing import Optional

# hashlib や bcrypt などのハッシュ化ライブラリは、要件に合わせて今回は使用しない
# import secrets # 今回の要件では不要

app = FastAPI(
    title="JHC35_FJJ ヘルスケア事業本部 アカウント認証型APIサーバ", # 問題文のタイトルに合わせる
    description="アカウント認証型APIサーバーの実装課題。", # 問題文に合わせて説明を更新
)

security = HTTPBasic()

# ダミーのユーザーデータベース (実際はDBを使う)
# 要件に合わせてテストアカウントとパスワードを直接設定
users_db = {
    # 予約されたテストアカウント
    "TaroYamada": {
        "password": "PaSSwd4TY", # 要件に合わせてパスワードを平文で保存 (※本番環境では絶対にNG！)
        "nickname": "たろー",
        "comment": "僕は元気です"
    },
    # その他のダミーユーザー（テスト用に維持する場合は残す）
    "testuser": {
        "password": "resurtset", # user_idを逆順にしたダミーパスワード
        "nickname": "Test User",
        "comment": "This is a test user.",
    },
}

# --- モデル定義 ---
class SignupRequest(BaseModel):
    # user_idのpatternに'_'は要件にないが、もし必要なら含める
    user_id: str = Field(..., min_length=6, max_length=20, pattern=r"^[a-zA-Z0-9]+$") # 要件は半角英数字のみ
    # passwordのpatternも要件は半角英数字記号 (空白と制御コードを除くASCII文字) なので、現状の[!-~]でOK
    password: str = Field(..., min_length=8, max_length=20, pattern=r"^[!-~]+$") 

class UserResponse(BaseModel):
    user_id: str
    nickname: str
    comment: Optional[str] = None # comment は Optional に

class UserUpdateRequest(BaseModel):
    nickname: Optional[str] = Field(None, max_length=30)
    comment: Optional[str] = Field(None, max_length=100)

    # 少なくともどちらか一方が指定されていることをバリデーション
    # Pydantic v2.x: @model_validator(mode='after') を使うか、__init__をオーバーライドする方法も
    # 今回は簡易的にメソッドとして定義
    def check_at_least_one_field(self):
        if self.nickname is None and self.comment is None:
            raise ValueError("nickname または comment のどちらか一方は必須です")
        return self

# --- ヘルパー関数 ---

# 認証処理
def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    current_user_id = credentials.username
    current_password = credentials.password

    if current_user_id not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    if current_password != users_db[current_user_id]["password"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return credentials.username

# --- エンドポイントの実装 ---

@app.post("/signup", summary="ユーザーアカウントの作成")
async def signup(request: SignupRequest):
    if request.user_id in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Account creation failed", "cause": "Already same user_id is used"}
        )
    
    users_db[request.user_id] = {
        "password": request.password,
        "nickname": request.user_id, # 初期値はuser_id
        "comment": None # 初期値はNone
    }
    return {
        "message": "Account successfully created",
        "user": {
            "user_id": request.user_id,
            "nickname": request.user_id
        }
    }

# パスパラメータ名を userid から user_id に修正して統一
@app.get("/users/{user_id}", response_model=UserResponse, summary="ユーザー情報の取得")
async def get_user_info(user_id: str, authenticated_user: str = Depends(authenticate_user)):
    user_data = users_db.get(user_id)
    if not user_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": "No user found"})
    
    # 仕様に合わせて nickname が未設定の場合は user_id と同じ値を返す
    # 今回のusers_db初期値とsignupロジックでは自動的に user_id と同じになる
    returned_nickname = user_data.get("nickname", user_id) 
    
    return UserResponse(user_id=user_id, nickname=returned_nickname, comment=user_data.get("comment"))


# パスパラメータ名を userid から user_id に修正して統一
@app.patch("/users/{user_id}", response_model=UserResponse, summary="ユーザー情報の更新")
async def update_user_info(
    user_id: str,
    update_request: UserUpdateRequest, # 変数名を update_request に変更して衝突を避ける
    authenticated_user: str = Depends(authenticate_user)
):
    if user_id != authenticated_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"message": "No permission for update"})

    if user_id not in users_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": "No User found"})

    # リクエストボディのバリデーションはPydanticモデルが自動で行うため、ValueErrorを捕捉
    try:
        update_request.check_at_least_one_field() # update_request のメソッドを呼び出す
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "Update failed", "cause": str(e)})

    current_user_data = users_db[user_id]

    # nickname と comment の更新
    if update_request.nickname is not None:
        # PydanticのFieldでmax_lengthを指定しているので、ここでは明示的な長さチェックは不要だが、
        # 問題の仕様に厳密に合わせるなら以下のように記述
        # if not (1 <= len(update_request.nickname) <= 30):
        #      raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "User update failed", "cause": "Invalid nickname length."})
        current_user_data["nickname"] = update_request.nickname
    
    if update_request.comment is not None:
        # PydanticのFieldでmax_lengthを指定しているので、ここでは明示的な長さチェックは不要だが、
        # 問題の仕様に厳密に合わせるなら以下のように記述 (コメントは0文字も許容される場合)
        # if not (0 <= len(update_request.comment) <= 100):
        #     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": "User update failed", "cause": "Invalid comment length."})
        current_user_data["comment"] = update_request.comment
    
    users_db[user_id] = current_user_data # 更新を反映

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
    # ユーザーが存在する場合に削除
    if authenticated_user in users_db: 
        del users_db[authenticated_user]
        return {"message": "Account and user successfully removed."}
    else: # 認証済みだがユーザーが見つからない（通常ありえないケース）
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "No user found to remove."},
        )

# --- 開発用の実行コマンド ---
if __name__ == "__main__":
    import uvicorn
    import os
    
    # 環境変数PORTが設定されていればそれを使用、なければ8000
    port = int(os.environ.get("PORT", 8000)) 
    uvicorn.run(app, host="0.0.0.0", port=port)
