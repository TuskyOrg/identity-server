# https://frankie567.github.io/fastapi-users/configuration/full-example.html

import secrets
import unicodedata
from typing import Optional, Dict, Any, Awaitable, Type, Union

import databases
import sqlalchemy
from fastapi import FastAPI, Request
from fastapi_users import (
    FastAPIUsers,
    authentication as fast_authentication,
    db as fast_db,
    password as fast_password,
    models as fast_models,
    user as fast_user
)
import fastapi_operation_id
from pydantic import BaseModel, BaseSettings, PostgresDsn, validator
from snowflake import get_snowflake, Snowflake
from sqlalchemy import Column, TEXT, BIGINT
from sqlalchemy.ext.declarative import DeclarativeMeta, declarative_base


class Settings(BaseSettings):
    SECRET_KEY = secrets.token_urlsafe(32)

    POSTGRES_SERVER: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    DATABASE_DSN: Optional[PostgresDsn] = None

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

    class Config:
        case_sensitive = True


settings = Settings()


def to_id(text):
    """ Normalizes utf-8 strings using normalization form KD and lowercase characters """
    # https://unicode.org/reports/tr15/
    #   For each character, there are two normal forms: normal form C and normal form D.
    #   Normal form D (NFD) is also known as canonical decomposition,
    #   and translates each character into its decomposed form.
    #   Normal form C (NFC) first applies a canonical decomposition,
    #   then composes pre-combined characters again...
    #   The normal form KD (NFKD) will apply the compatibility decomposition,
    #   i.e. replace all compatibility characters with their equivalents.
    normalized_text: str = unicodedata.normalize("NFKD", text).lower()
    banned_symbols = ["$", "@", "!", "admin"]
    if any(s in normalized_text for s in banned_symbols):
        raise
    if len(normalized_text) < 3:
        raise
    return normalized_text


class CreateUpdateDictModel(BaseModel):
    """ Custom implementation of fast_models.CreateUpdateDictModel """
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
                "snowflake"
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
    snowflake: Optional[Snowflake]
    username: Optional[str]
    username_id: Optional[str]



class UserCreate(CreateUpdateDictModel, fast_models.BaseUserCreate, ):
    username: str


class UserUpdate(User, fast_models.BaseUserUpdate):
    pass


class UserInDB(User, fast_models.BaseUserDB):
    username: str


database = databases.Database(settings.DATABASE_DSN)
Base: DeclarativeMeta = declarative_base()


class UserTable(Base, fast_db.SQLAlchemyBaseUserTable):
    snowflake = Column(BIGINT, nullable=False, unique=True, index=True)
    username = Column(TEXT, nullable=False)
    username_id = Column(TEXT, unique=True, nullable=False, index=True)


engine = sqlalchemy.create_engine(settings.DATABASE_DSN, echo=True)


def initdb() -> None:
    Base.metadata.create_all(engine)
    # Todo: Check if superuser exists; if not, create it


def dropdb() -> None:
    Base.metadata.drop_all(engine)


users = UserTable.__table__


class TuskyUserDatabase(fast_db.SQLAlchemyUserDatabase):
    # Add a methods to get users by snowflake and username

    async def create(self, user: fast_models.UD) -> fast_models.UD:
        user.snowflake = await get_snowflake()
        return await super(TuskyUserDatabase, self).create(user)

    async def get_by_username(self, username: str):
        username_id = to_id(username)
        query = self.users.select().where(self.users.c.username_id == username_id)
        user = await self.database.fetch_one(query)
        return await self._make_user(user) if user else None

    async def get_by_snowflake(self, snowflake: Union[Snowflake, int]):
        query = self.users.select().where(self.users.c.snowflake == snowflake)
        user = await self.database.fetch_one(query)
        return await self._make_user(user) if user else None


user_db = TuskyUserDatabase(
    user_db_model=UserInDB, database=database, users=users
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

# TODO: mypy is angry about typing but I don't see what's wrong


def get_create_user(
    user_db: fast_db.base.BaseUserDatabase[fast_models.BaseUserDB],
    user_db_model: Type[fast_models.BaseUserDB],
) -> fast_user.CreateUserProtocol:
    # The implementation is matched fairly one to one from fast_user.get_create_user
    async def create_user(
        user: UserCreate,
        safe: bool = True,
        is_active: bool = None,
        is_verified: bool = None,
    ) -> fast_models.BaseUserDB:
        # Verify user doesn't already exist
        existing_email = await user_db.get_by_email(user.email)
        if existing_email is not None:
            raise fast_user.UserAlreadyExists()
        existing_username = await user_db.get_by_username(user.username)
        if existing_username is not None:
            raise fast_user.UserAlreadyExists()

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
app.include_router(fast_users.get_users_router(), prefix="/users", tags=["users"])


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


fastapi_operation_id.clean_ids(app)
