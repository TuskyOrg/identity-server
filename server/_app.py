# https://frankie567.github.io/fastapi-users/configuration/full-example.html
import datetime
import logging
import os
import pathlib
import secrets
from typing import Optional, Dict, Any, Type, Literal
import warnings
import unicodedata

import databases
from asyncpg.exceptions import UniqueViolationError
from databases import Database
from fastapi import FastAPI, Request, status
from fastapi.exceptions import HTTPException
from fastapi.responses import Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users import (
    FastAPIUsers,
    # Naming schema: All modules from fastapi_users are labeled as fast_<module_name>.
    authentication as fast_authentication,
    db as fast_db,
    password as fast_password,
    models as fast_models,
    utils as fast_utils,
    user as fast_user,
)
import jwt
from pydantic import BaseModel, BaseSettings, EmailStr, PostgresDsn, validator, Field
from tusky_snowflake import get_snowflake, synchronous_get_snowflake, Snowflake
from sqlalchemy import create_engine  # type: ignore
from sqlalchemy.ext.declarative import DeclarativeMeta, declarative_base  # type: ignore
from sqlalchemy.sql import func  # type: ignore
from sqlalchemy.sql.expression import text, desc  # type: ignore
from sqlalchemy.sql.schema import Column, ForeignKey, Table  # type: ignore
from sqlalchemy.types import TEXT, BIGINT, String, BOOLEAN, TIMESTAMP  # type: ignore


class Settings(BaseSettings):
    IS_PRODUCTION: bool = False

    # TODO: PRODUCTION KEY
    SECRET_KEY = "abcdefghijklmnop"  # secrets.token_urlsafe(32)

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

    TOKEN_AUDIENCE_AUTH: str = "tusky-identity-service:auth"

    REFRESH_SECRET: str = "ponmlkjihgfedcba"
    REFRESH_LIFETIME_SECONDS: int = 1209600  # 2 Weeks

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
    if len(normalized_text) < 2:
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


# Todo: it would be nice to keep a consistent style, but this class isn't actually used
# class RefreshTokenCreateUpdateDictModel(BaseModel):
#     def create_update_dict(self): return self.dict(exclude_unset=True, include={"revoked"})
#     create_update_dict_superuser = create_update_dict()


class UserModel(CreateUpdateDictModel, fast_models.BaseUser):
    id: Optional[Snowflake]
    username: Optional[str]


class UserModelCreate(CreateUpdateDictModel, fast_models.BaseUserCreate):
    username: str
    email: Optional[EmailStr]


class UserModelUpdate(UserModel, fast_models.BaseUserUpdate):
    pass


class UserModelInDB(UserModel, fast_models.BaseUserDB):
    # Todo: I know my typing is incorrect but it doesn't seem worth it to figure out a fix
    # The function "create_user" has the line "db_user = user_db_model(...".
    # This requires that the Pydantic object be already created
    # However, the Snowflake is only fetched when inserting into the database.
    # We lie to the type checker by saying id (Snowflake) is an optional field,
    # despite it being required by the database.
    id: Optional[Snowflake]
    email: Optional[EmailStr]
    username: str
    username_id: str


class RefreshTokenModel(BaseModel):
    id: Optional[Snowflake]
    user_id: Snowflake
    token: str
    is_revoked: bool = False
    creation_timestamp: Optional[datetime.datetime]


class RefreshTokenModelInDB(RefreshTokenModel):
    id: Snowflake
    creation_timestamp = datetime.datetime

    class Config:
        orm_mode = True


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"]


class RefreshParameters(BaseModel):
    # https://auth0.com/docs/api/authentication?http#refresh-token
    grant_type: Literal["refresh_token"]
    client_id: str = Field(..., description="The user's id (Snowflake) as a string")
    # client_secret: str
    refresh_token: str
    # A URL-encoded space-delimited list of requested scope permissions
    scope: Optional[str]


class RevokeParameters(BaseModel):
    client_id: str
    token: str


class RefreshResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"]


db = databases.Database(settings.DATABASE_DSN)  # type: ignore
Base: DeclarativeMeta = declarative_base()


class UserTable(Base, fast_db.SQLAlchemyBaseUserTable):
    __tablename__ = "users"

    id = Column(BIGINT, primary_key=True, index=True, nullable=True, default=None)
    email = Column(String(length=320), unique=True, index=False, nullable=True)
    username = Column(TEXT, nullable=False)
    username_id = Column(TEXT, unique=True, nullable=False, index=True)


class RefreshTokenTable(Base):
    __tablename__ = "refresh_tokens"
    id = Column(BIGINT, primary_key=True, index=True, nullable=True, default=None)
    user_id = Column(BIGINT, ForeignKey("users.id"), index=True, nullable=False)
    # Todo: logic ensuring ACTIVE refresh_tokens unique (not ALL refresh_tokens unique)
    token = Column(TEXT, nullable=False, unique=True)
    is_revoked = Column(BOOLEAN, default=False)
    creation_timestamp = Column(TIMESTAMP, server_default=func.current_timestamp())


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
    id_ = synchronous_get_snowflake()
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


class CRUDUser(fast_db.SQLAlchemyUserDatabase):
    # Add a methods to get users by snowflake and username

    async def create(self, user: UserModelInDB) -> UserModelInDB:
        user.id = await get_snowflake()
        return await super(CRUDUser, self).create(user)

    async def get_by_username(self, username: str) -> UserModelInDB:
        username_as_id = to_id(username)
        query = self.users.select().where(self.users.c.username_id == username_as_id)
        user = await self.database.fetch_one(query)
        return await self._make_user(user) if user else None

    # We redefine the behavior to accept a username OR email as authentication
    async def authenticate(
        self, credentials: OAuth2PasswordRequestForm
    ) -> Optional[UserModelInDB]:
        """
        Authenticate and return a user following a username or email and a password.

        Will automatically upgrade password hash if necessary.
        """
        # https://github.com/frankie567/fastapi-users/blob/728c160b50112b6cd522ecddbe409b3d08ea7805/fastapi_users/db/base.py#L46
        if "@" in credentials.username:
            user = await self.get_by_email(credentials.username)
        else:
            user = await self.get_by_username(credentials.username)
        # https://github.com/frankie567/fastapi-users/blob/728c160b50112b6cd522ecddbe409b3d08ea7805/fastapi_users/db/base.py#L46
        if user is None:
            # Run the hasher to mitigate timing attack
            # Inspired from Django: https://code.djangoproject.com/ticket/20760
            fast_password.get_password_hash(credentials.password)
            return None

        verified, updated_password_hash = fast_password.verify_and_update_password(
            credentials.password, user.hashed_password
        )
        if not verified:
            return None
        # Update password hash to a more robust one if needed
        if updated_password_hash is not None:
            user.hashed_password = updated_password_hash
            await self.update(user)

        return user


class CRUDRefreshToken:
    # Todo: typing generic BaseModel
    def __init__(
        self, token_db_model: Type[BaseModel], database: Database, tokens: Table
    ):
        self.token_db_model = token_db_model
        self.database = database
        self.tokens = tokens

    async def get_by_token(self, token: str) -> Optional[RefreshTokenModelInDB]:
        query = (
            self.tokens.select()
            .where(self.tokens.c.token == token)
            .order_by(desc(self.tokens.c.creation_timestamp))
        )
        token_data = await self.database.fetch_one(query)
        return self.token_db_model(**token_data) if token_data else None

    # Todo: typing: this should be a refreshtokenmodel in db to fit the schema, but it doesn't work
    async def create(self, token: RefreshTokenModelInDB) -> RefreshTokenModelInDB:
        token.id = await get_snowflake()
        token_data = token.dict()
        query = self.tokens.insert()
        await self.database.execute(query, token_data)
        return token

    async def revoke(self, token: RefreshTokenModelInDB):
        query = (
            self.tokens.update()
            .where(self.tokens.c.token == token.token)
            .values(is_revoked=True)
        )
        await self.database.execute(query, {"token": token.token})


crud_user = CRUDUser(
    user_db_model=UserModelInDB, database=db, users=UserTable.__table__
)
crud_refresh_token = CRUDRefreshToken(
    token_db_model=RefreshTokenModelInDB,
    database=db,
    tokens=RefreshTokenTable.__table__,
)


def on_after_register(user: UserModelInDB, request: Request):
    # print(f"User {user.id} has registered.")
    print("Registerd user: ", user)


# def on_after_forgot_password(user: UserInDB, token: str, request: Request):
#     print(f"User {user.id} has forgot their password. Reset token: {token}")


def after_verification_request(user: UserModelInDB, token: str, request: Request):
    print(f"Verification requested for user {user.id}. Verification token: {token}")


class JWTAuthentication(fast_authentication.JWTAuthentication):
    token_audience = settings.TOKEN_AUDIENCE_AUTH
    # JWT_ALGORITHM = "HS256" # its defined in fast_utils.JWT_ALGORITHM

    # todo: To remain consistent with fast_authentication.JWTAuthentication,
    #  these attributes should be set in __init__
    #  Additionally, "secret" should be aliased to "user_secret".
    #  Maybe these should be all caps?
    refresh_secret: str
    refresh_lifetime_seconds: str

    # Details that force us to redefine __call__:
    #       We use Snowflakes instead of UUID's
    #       We use the field "sub" instead of "user_id"
    # https://github.com/frankie567/fastapi-users/blob/728c160b50112b6cd522ecddbe409b3d08ea7805/fastapi_users/authentication/jwt.py#L41
    async def __call__(
        self,
        credentials: Optional[str],
        user_db: CRUDUser,
    ) -> Optional[UserModelInDB]:
        if credentials is None:
            return None

        try:
            data = jwt.decode(
                credentials,
                self.secret,
                audience=self.token_audience,
                algorithms=[fast_utils.JWT_ALGORITHM],
            )
            user_id = data.get("sub")
            if user_id is None:
                return None
        except jwt.PyJWTError as err:
            # Todo: Actually log errors
            print(err)
            return None

        try:
            user_id = int(user_id)
            return await user_db.get(user_id)
        except ValueError:
            return None

    async def get_login_response(
        self, user: UserModelInDB, response: Response
    ) -> LoginResponse:
        # THIS FUNCTION WRITES TO THE REFRESH TOKEN TABLE
        # Todo: Separation of concerns: this should not be writing to the database,
        #  at least without the name indicating as such).
        #  It's hard to refactor without breaking get_auth_router,
        #  but get_login_response should take a CRUDRefreshToken as an argument
        #  (like __init__ takes a CRUDUser as an argument)
        user_id = str(user.id)
        access_token = self._generate_access_token(user_id)
        refresh_token = self._generate_refresh_token(user_id)
        token_model = RefreshTokenModel(user_id=user.id, token=refresh_token)
        await crud_refresh_token.create(token_model)
        return LoginResponse(
            access_token=access_token, refresh_token=refresh_token, token_type="bearer"
        )

    async def get_refresh_response(
        self, token_data: RefreshTokenModelInDB, response: Response
    ) -> RefreshResponse:
        # This method's odd signature mimics the signature of the base class's
        # get_*_response methods
        access_token = self._generate_access_token(str(token_data.user_id))
        return RefreshResponse(access_token=access_token, token_type="bearer")

    def __generate_token(
        self, user_id: str, secret, lifetime_seconds, extras: Dict = None
    ) -> str:
        # We use "sub" instead of "user_id"
        # Todo: "aud"
        data = {"sub": user_id, "aud": settings.TOKEN_AUDIENCE_AUTH}
        if extras:
            data.update(extras)
        return fast_utils.generate_jwt(
            data, secret, lifetime_seconds, fast_utils.JWT_ALGORITHM
        )

    def _generate_access_token(self, user_id: str) -> str:
        return self.__generate_token(user_id, self.secret, self.lifetime_seconds)

    # Adding the refresh_secret and refresh_lifetime seconds to JWTAuthentication itself
    # just to mimic the library is silly; instead, we have them defined in settings
    def _generate_refresh_token(self, user_id: str) -> str:
        extras = {"rand": secrets.randbits(64)}
        return self.__generate_token(
            user_id,
            settings.REFRESH_SECRET,
            settings.REFRESH_LIFETIME_SECONDS,
            extras=extras,
        )

    # TODO: LOGOUT ENDPOINT
    logout = False

    async def get_logout_response(self, user: UserModelInDB, response: Response):
        raise NotImplementedError


jwt_authentication = JWTAuthentication(
    secret=settings.SECRET_KEY, lifetime_seconds=3600, tokenUrl="auth/jwt/login"
)

app = FastAPI(title="Identity Service")

origins = ["http://tusky.org", "http://localhost:5000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Some notes on fastapi_users:
#   fastapi_users is smart. By default, a "safe" mode is enabled that does not allow
#   clients accessing the api set is_superuser or is_active, etc
#
# Let's walk through how the library works so we know how to edit it
# We start by creating a FastAPIUsers object
# Note fast_user is fastapi_users.user, while fast_users is the FastAPIUsers object
fast_users = FastAPIUsers(
    db=crud_user,
    auth_backends=[jwt_authentication],
    user_model=UserModel,
    user_create_model=UserModelCreate,
    user_update_model=UserModelUpdate,
    user_db_model=UserModelInDB,
)


# The object has methods that return routes.
# These methods are a thin wrapper around functions in the fastapi_users library.
# For example, fast_users.get_auth_router internally calls fastapi_users.router.get_auth_router
#
# fast_users.get_auth_router has fewer arguments than fastapi_users.router.get_auth_router
# Instead of the method having more parameters, it passes object attributes to the function.
# Thus, to edit the behavior of the router, we assign specific object attributes to our implementation
def get_create_user(
    user_db: CRUDUser,
    user_db_model: Type[UserModelInDB],
) -> fast_user.CreateUserProtocol:
    async def create_user(
        user: fast_models.BaseUserCreate,
        safe: bool = True,
        is_active: bool = None,
        is_verified: bool = None,
    ) -> fast_models.BaseUserDB:
        # See fast_user.get_create_user for default implementation
        hashed_password = fast_password.get_password_hash(user.password)
        user_dict = user.create_update_dict_superuser()
        # user_dict = user.create_update_dict() if safe else user.create_update_dict_superuser()
        db_user = user_db_model(
            **user_dict,
            hashed_password=hashed_password,
        )
        try:
            user = await user_db.create(db_user)
        except UniqueViolationError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Duplicate user"
            )
        return user

    return create_user


fast_users.create_user = get_create_user(crud_user, UserModelInDB)

# Now that we've set fast_users's "create_user" attribute,
# the method "get_register_router" will use our custom implementation
app.include_router(
    fast_users.get_register_router(on_after_register), prefix="/auth", tags=["auth"]
)
auth_router = fast_users.get_auth_router(jwt_authentication)
for r in auth_router.routes:
    if r.name == "login":
        r.response_model = LoginResponse


async def _handle_token(refresh_token: str, client_id: str):
    token = await crud_refresh_token.get_by_token(refresh_token)
    if (token is None) or token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token",
        )
    if token.user_id != int(client_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid refresh token"
        )
    return token


# Todo: to stay true to the fastapi_users framework, the "proper" way to write this
#  would be to set fast_users.get_auth_router to include our implementation
# Todo: Add ip_address
@auth_router.post("/refresh", response_model=RefreshResponse)
async def refresh(response: Response, obj_in: RefreshParameters):
    token = await _handle_token(obj_in.refresh_token, obj_in.client_id)
    return await jwt_authentication.get_refresh_response(token, response)


@auth_router.post("/revoke")
async def revoke(obj_in: RevokeParameters):
    token = await _handle_token(obj_in.token, obj_in.client_id)
    await crud_refresh_token.revoke(token)
    return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)


app.include_router(auth_router, prefix="/auth/jwt", tags=["auth"])
# Todo: Add reset password logic
# app.include_router(
#     fast_users.get_reset_password_router(
#         settings.SECRET_KEY, after_forgot_password=on_after_forgot_password
#     ),
#     prefix="/auth",
#     tags=["auth"],
# )
# Todo: Set up email verification (and rename router); in the meantime, the email verification route is removed
# app.include_router(
#     fast_users.get_verify_router(settings.SECRET_KEY),
#     prefix="/auth",
#     tags=["auth"],
# )
# We do not need custom routes for updating users (In fact, the only route fast_users.router lets you modify directly is "validate_password");
# However, there fast_users has attributes set that modify the default behavior
#
# User inherits from CreateUpdateDictModel (which defines update logic)
# The dependency "current_active_user" is modified using the jwt_authentication backend;
users_router = fast_users.get_users_router()
# We don't want any superuser routes
users_router.routes = [
    r
    for r in users_router.routes
    if r.name not in ("delete_user", "update_user", "get_user")
]
app.include_router(users_router, prefix="/users", tags=["users"])


@app.on_event("startup")
async def startup():
    await db.connect()
    initdb()


@app.on_event("shutdown")
async def shutdown():
    await db.disconnect()
