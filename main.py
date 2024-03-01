from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, URL, text, MetaData
from sqlalchemy import Table, Integer, Column, String, TIMESTAMP
from sqlalchemy.sql import insert, select, literal_column
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv
from os import getenv
from pydantic import BaseModel, EmailStr
from typing import Annotated, Union
from passlib.context import CryptContext
from jose import JWTError, jwt


app = FastAPI()
metadata = MetaData()

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(255), nullable=False, unique=True),
    Column("email", String(255), nullable=False, unique=True),
    Column("password", String(255), nullable=False),
    Column("first_name", String(255)),
    Column("last_name", String(255)),
    Column("created_at", TIMESTAMP, server_default=text('CURRENT_TIMESTAMP')),
    Column("updated_at", TIMESTAMP, server_default=text('CURRENT_TIMESTAMP')),
)


load_dotenv()

DB_HOST = getenv("DB_HOST")
DB_USER = getenv("DB_USER")
DB_PASSWORD = getenv("DB_PASSWORD")
DB_PORT = getenv("DB_PORT")
DB_NAME = getenv("DB_NAME")
ACCESS_TOKEN_EXPIRE_MINUTES = getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
ALGORITHM = getenv("ALGORITHM")
SECRET_KEY = getenv("SECRET_KEY")

DB_URL = URL.create(
    "postgresql+pg8000",
    username=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    database=DB_NAME,
    port=DB_PORT,
)

engine = create_engine(DB_URL)


class UserBase(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    username: str
    email: EmailStr


class UserIn(UserBase):
    password: str


class UserOut(UserBase):
    id: int


class UserInDatabase(UserOut):
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


ouath2_scheme = OAuth2PasswordBearer(tokenUrl='login')
pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")


def get_password_hash(password) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username: str) -> UserInDatabase:
    select_stmt = select(users_table).where(users_table.c.username == username)
    with engine.connect() as conn:
        try:
            result = conn.execute(select_stmt)
            user_data = result.fetchone()._asdict()
            if user_data.keys() == 0:
                raise Exception("User not found")
            return user_data
        except Exception as e:
            print(e)
            return {}


def get_user_public_data(user: UserInDatabase) -> UserOut:
    del user['created_at']
    del user['updated_at']
    del user['password']
    return user


def get_authenticated_user(
        username: str,
        password: str
) -> Union[UserOut, False]:
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    user_data = get_user_public_data(user)
    return user_data


def create_access_token(
        data: dict,
        expires_delta: Union[timedelta, None] = None
):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_access_token(
        token: Annotated[str, Depends(ouath2_scheme)]
) -> UserOut:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate",
    )
    try:
        payload: dict = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user_public_data(get_user(token_data.username))
    if user is None:
        raise credentials_exception
    return user


@app.post("/register")
def register(user: UserIn):
    hashed_password: str = get_password_hash(user.password)
    insert_stmt = insert(users_table).values(
        username=user.username,
        email=user.email,
        password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
    ).returning(literal_column('*'))

    with engine.connect() as conn:
        try:
            result = conn.execute(insert_stmt)
            conn.commit()
            user_data = result.fetchone()._asdict()
            response_user = get_user_public_data(user_data)
            return {
                "message": "User created successfully",
                "user": response_user
            }
        except IntegrityError as e:
            if "unique constraint" in str(e):
                raise HTTPException(
                    status_code=400, detail="Username or email already exists."
                )
            else:
                raise HTTPException(
                    status_code=500, detail="Database error."
                )


@app.post("/login")
def login(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = get_authenticated_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    access_token = create_access_token(
        data={"sub": user['username']}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/whoami")
def whoami(current_user: Annotated[UserOut, Depends(verify_access_token)]) -> UserOut:
    return current_user
