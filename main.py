from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordRequestForm
from schemas import User, Token
from fake_db import fake_users_db
from get_current_user import get_current_user
from authenticate_user import authenticate_user
from create_access_token import create_access_token




def get_current_active_user(current_user: User = Security(get_current_user, scopes=["user"])):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Usuario deshabilitado")
    return current_user

def get_current_rol_user(current_user: User = Security(get_current_user, scopes=["user", "admin"])):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Usuario deshabilitado")
    return current_user

app = FastAPI()


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.username, "scopes": form_data.scopes})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
def read_own_items(current_user: User = Security(get_current_active_user, scopes=["admin"])):
    return [fake_users_db]

@app.get("/users/me/items/other_method", dependencies=[Depends(get_current_rol_user)])
def read_own_items_dos():
    return [fake_users_db]


@app.get("/status/")
def read_system_status(current_user: User = Depends(get_current_user)):
    status = "Inactive" if current_user.disabled is True else "Active"
    return {"status": status}