from fastapi import FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine, URL, text, MetaData
from sqlalchemy import Table, Integer, Column, String, TIMESTAMP
from sqlalchemy.sql import insert, select
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv
from os import getenv
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Annotated
from passlib.context import CryptContext


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
    created_at: datetime | None = None
    updated_at: datetime | None = None


ouath2_scheme = OAuth2PasswordBearer(tokenUrl='login')
pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")


def get_password_hash(password) -> str:
    return pwd_context.hash(password)


@app.get("/welcome")
async def welcome():
    return {"message": "hi there"}


@app.post("/register")
async def register(user: UserIn):
    hashed_password: str = get_password_hash(user.password)
    insert_stmt = insert(users_table).values(
        username=user.username,
        email=user.email,
        password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
    )

    with engine.connect() as conn:
        try:
            result = conn.execute(insert_stmt)
            conn.commit()
            select_stmt = select(users_table).where(
                users_table.c.id == result.inserted_primary_key[0]
            )
            select_result = conn.execute(select_stmt)
            user_data = select_result.fetchone()._asdict()
            del user_data['password']
            return {"message": "User created successfully", "user": user_data}
        except IntegrityError as e:
            if "unique constraint" in str(e):
                raise HTTPException(
                    status_code=400, detail="Username or email already exists."
                )
            else:
                raise HTTPException(
                    status_code=500, detail="Database error."
                )
