from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from fastapi import status, Depends, HTTPException
from pydantic import ValidationError
from jose import jwt, JWTError
from fake_db import fake_users_db
from schemas import TokenData
from get_user import get_user

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={"user": "Read information about the current user.", "admin": "Read all data with items."},
)

#metodo para obtener el usuario actual
def get_current_user(security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = f"Bearer"

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales invalidas",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload     = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username    = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes    = payload.get("scopes", [])
        token_data      = TokenData(scopes=token_scopes, username=username)

    except (JWTError, ValidationError):
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)

    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No tienes permiso",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user


