# https://frankie567.github.io/fastapi-users/configuration/full-example.html

import logging
import os
import pathlib
import secrets
from typing import Optional, Dict, Any, Type
import warnings
import unicodedata

import databases
from fastapi import FastAPI, APIRouter, Request
from fastapi_users import (
    FastAPIUsers,
    # Naming schema: All modules from fastapi_users are labeled as fast_<module_name>.
    authentication as fast_authentication,
    db as fast_db,
    password as fast_password,
    models as fast_models,
    user as fast_user,
)
import fastapi_operation_id
from pydantic import BaseModel, BaseSettings, EmailStr, PostgresDsn, validator
from snowflake import get_snowflake, Snowflake
from sqlalchemy import create_engine  # type: ignore
from sqlalchemy.ext.declarative import DeclarativeMeta, declarative_base  # type: ignore
from sqlalchemy.sql.expression import text  # type: ignore
from sqlalchemy.sql.schema import Column  # type: ignore
from sqlalchemy.types import TEXT, BIGINT  # type: ignore


class Settings(BaseSettings):
    SECRET_KEY = secrets.token_urlsafe(32)

    POSTGRES_SERVER: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    DATABASE_DSN: Optional[PostgresDsn]

    @validator("DATABASE_DSN", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        return PostgresDsn.build(
            scheme="postgresql",
            user=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_SERVER"),
            path=f"/{values.get('POSTGRES_DB') or ''}",
        )

    FIRST_SUPERUSER_USERNAME: str
    FIRST_SUPERUSER_EMAIL: EmailStr
    FIRST_SUPERUSER_PASSWORD: str

    LOG_DIR: pathlib.PosixPath
    LOG_FILE_NAME: str
    LOG_FILE_PATH: Optional[str] = None

    @validator("LOG_FILE_PATH", pre=True)
    def assemble_log_file_path(cls, v: Optional[str], values):
        return os.path.join(values.get("LOG_DIR"), values.get("LOG_FILE_NAME"))

    class Config:
        case_sensitive = True


settings = Settings()


# Logic to log to a file
handler_level = logging.INFO
logger_level = logging.INFO

handler: logging.Handler
try:
    handler = logging.FileHandler(settings.LOG_FILE_PATH)  # type: ignore
except FileNotFoundError:
    warnings.warn("Log file not found; using NullHandler", UserWarning)
    handler = logging.NullHandler()
handler.setLevel(handler_level)

logger = logging.getLogger("sqlalchemy")
logger.addHandler(handler)
logger.setLevel(logger_level)


def to_id(text):
    """Normalizes utf-8 strings using normalization form KD and lowercase characters"""
    # https://unicode.org/reports/tr15/
    #   For each character, there are two normal forms: normal form C and normal form D.
    #   Normal form D (NFD) is also known as canonical decomposition,
    #   and translates each character into its decomposed form.
    #   Normal form C (NFC) first applies a canonical decomposition,
    #   then composes pre-combined characters again...
    #   The normal form KD (NFKD) will apply the compatibility decomposition,
    #   i.e. replace all compatibility characters with their equivalents.
    normalized_text: str = unicodedata.normalize("NFKD", text).lower()
    banned_symbols = ["$", "@", "!"]
    if any(s in normalized_text for s in banned_symbols):
        raise
    if len(normalized_text) < 3:
        raise
    return normalized_text


class CreateUpdateDictModel(BaseModel):
    """Custom implementation of fast_models.CreateUpdateDictModel"""

    # fast_models.BaseUser inherits from fast_models.CreateUpdateDictModel.
    # We want our User to inherit from fast_models.BaseUser
    # but with custom behavior these two methods.
    #
    # As such, User (and CreateUser) inherit from this CreateUpdateDictModel and THEN
    # from fast_models.BaseUser (or fast_models.UserCreate).
    # Otherwise, these methods would be overrode by fast_models.BaseUser

    def create_update_dict(self):
        d = self.dict(
            exclude_unset=True,
            exclude={
                "id",
                "is_superuser",
                "is_active",
                "is_verified",
                "oauth_accounts",
                "snowflake",
            },
        )
        if d["username"]:
            d["username_id"] = to_id(d["username"])
        return d

    def create_update_dict_superuser(self):
        d = self.dict(exclude_unset=True, exclude={"id", "snowflake"})

        if d["username"]:
            d["username_id"] = to_id(d["username"])
        return d


class User(CreateUpdateDictModel, fast_models.BaseUser):
    id: Optional[Snowflake]
    username: Optional[str]
    username_id: Optional[str]


class UserCreate(CreateUpdateDictModel, fast_models.BaseUserCreate):
    username: str


class UserUpdate(User, fast_models.BaseUserUpdate):
    pass


class UserInDB(User, fast_models.BaseUserDB):
    id: Snowflake
    username: str
    username_id: str


database = databases.Database(settings.DATABASE_DSN)  # type: ignore
Base: DeclarativeMeta = declarative_base()


class UserTable(Base, fast_db.SQLAlchemyBaseUserTable):
    __tablename__ = "users"

    id = Column(BIGINT, primary_key=True, index=True, nullable=True, default=None)
    username = Column(TEXT, nullable=False)
    username_id = Column(TEXT, unique=True, nullable=False, index=True)


engine = create_engine(settings.DATABASE_DSN, echo=False)


def initdb():
    Base.metadata.create_all(engine)

    # I had difficulty working with the 'databases' library, so I just wrote the sql by hand

    # Check if superuser (admin) account exists.
    with engine.connect() as conn:
        select_statement = text("SELECT username FROM users WHERE username_id = :name;")
        result = conn.execute(
            select_statement, {"name": to_id(settings.FIRST_SUPERUSER_USERNAME)}
        )
        user_exists: int = result.rowcount
    if user_exists:
        return

    # If it doesn't, create it
    import asyncio

    loop = asyncio.get_event_loop()
    task = loop.create_task(get_snowflake())
    #
    id_ = loop.run_until_complete(task)
    username_id = to_id(settings.FIRST_SUPERUSER_USERNAME)
    hashed_password = fast_password.get_password_hash(settings.FIRST_SUPERUSER_PASSWORD)
    user_model = {
        "id": id_,
        "username": settings.FIRST_SUPERUSER_USERNAME,
        "username_id": username_id,
        "email": settings.FIRST_SUPERUSER_EMAIL,
        "hashed_password": hashed_password,
        "is_active": True,
        "is_verified": True,
        "is_superuser": True,
    }
    insert_statement = UserTable.__table__.insert().values(**user_model)
    with engine.begin() as conn:
        conn.execute(insert_statement)


def dropdb() -> None:
    Base.metadata.drop_all(engine)


class TuskyUserDatabase(fast_db.SQLAlchemyUserDatabase):
    # Add a methods to get users by snowflake and username

    async def create(self, user: UserInDB) -> UserInDB:
        user.id = await get_snowflake()
        return await super(TuskyUserDatabase, self).create(user)

    # This method is unused as of 2021/07/01.
    # However, the functionality is solid and it complements
    # fast_db.SQLAlchemyUserDatabase.get_by_email, so this dead code is left alone.
    async def get_by_username(self, username: str):
        username_id = to_id(username)
        query = self.users.select().where(self.users.c.username_id == username_id)
        user = await self.database.fetch_one(query)
        return await self._make_user(user) if user else None


user_db = TuskyUserDatabase(
    user_db_model=UserInDB, database=database, users=UserTable.__table__
)


def on_after_register(user: UserInDB, request: Request):
    # print(f"User {user.id} has registered.")
    print(user)
    print(user.dict())


def on_after_forgot_password(user: UserInDB, token: str, request: Request):
    print(f"User {user.id} has forgot their password. Reset token: {token}")


def after_verification_request(user: UserInDB, token: str, request: Request):
    print(f"Verification requested for user {user.id}. Verification token: {token}")


jwt_authentication = fast_authentication.JWTAuthentication(
    secret=settings.SECRET_KEY, lifetime_seconds=3600, tokenUrl="auth/jwt/login"
)

app = FastAPI()
# Some notes on fastapi_users:
#   fastapi_users is smart. By default, a "safe" mode is enabled that does not allow
#   clients accessing the api set is_superuser or is_active, etc
#
# Let's walk through how the library works so we know how to edit it
# We start by creating a FastAPIUsers object
# Note fast_user is fastapi_users.user, while fast_users is the FastAPIUsers object
fast_users = FastAPIUsers(
    db=user_db,
    auth_backends=[jwt_authentication],
    user_model=User,
    user_create_model=UserCreate,
    user_update_model=UserUpdate,
    user_db_model=UserInDB,
)


# The object has methods that return routes.
# These methods are a thin wrapper around functions in the fastapi_users library.
# For example, fast_users.get_auth_router internally calls fastapi_users.router.get_auth_router
#
# fast_users.get_auth_router has fewer arguments than fastapi_users.router.get_auth_router
# Instead of the method having more parameters, it passes object attributes to the function.
# Thus, to edit the behavior of the router, we assign specific object attributes to our implementation
def get_create_user(
    user_db: TuskyUserDatabase,
    user_db_model: Type[UserInDB],
) -> fast_user.CreateUserProtocol:
    async def create_user(
        user: fast_models.BaseUserCreate,
        safe: bool = True,
        is_active: bool = None,
        is_verified: bool = None,
    ) -> fast_models.BaseUserDB:
        # See fast_user.get_create_user for default implementation

        # We make the assumption that an integrity error means the user already exists
        # This could lead to bugs down the road if an integrity error occurs for a different reason,
        # but it saves us from hitting the database 2 additional times
        # to check if the email or username is already registered.
        hashed_password = fast_password.get_password_hash(user.password)
        user_dict = (
            user.create_update_dict() if safe else user.create_update_dict_superuser()
        )
        db_user = user_db_model(
            **user_dict,
            hashed_password=hashed_password,
        )
        return await user_db.create(db_user)

    return create_user


fast_users.create_user = get_create_user(user_db, UserInDB)

# Now that we've set fast_users's "create_user" attribute,
# the method "get_register_router" will use our custom implementation
app.include_router(
    fast_users.get_register_router(on_after_register), prefix="/auth", tags=["auth"]
)
app.include_router(
    fast_users.get_auth_router(jwt_authentication), prefix="/auth/jwt", tags=["auth"]
)
app.include_router(
    fast_users.get_reset_password_router(
        settings.SECRET_KEY, after_forgot_password=on_after_forgot_password
    ),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fast_users.get_verify_router(
        settings.SECRET_KEY, after_verification_request=after_verification_request
    ),
    prefix="/auth",
    tags=["auth"],
)
# We do not need custom attributes for updating users;
# User inherits from CreateUpdateDictModel (which defines update logic)
#
# In fact, the only route fast_users.router lets you modify directly is "validate_password"
app.include_router(fast_users.get_users_router(), prefix="/users", tags=["users"])


find_user = APIRouter()


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


fastapi_operation_id.clean_ids(app)
