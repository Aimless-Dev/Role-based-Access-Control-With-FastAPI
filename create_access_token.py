from get_current_user import SECRET_KEY, ALGORITHM
from jose import jwt

#crear access token
def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt