import httpx

########################################################################################
# Typing
########################################################################################
from typing import (
    Type,
    Union,
    TypeVar,
    Iterable,
    AsyncIterable,
    Any,
    Coroutine,
    Dict,
    Sequence,
    Tuple,
    MutableMapping,
    Protocol,
    Literal,
    Optional,
)

JWT = str
ClientType = Union[Type[httpx.Client], Type[httpx.AsyncClient]]
# https://github.com/encode/httpx/blob/ab64f7c41fc0fbe638dd586fecf0689c847109bb/httpx/_types.py
RequestContent = Union[str, bytes, Iterable[bytes], AsyncIterable[bytes]]
ResponseContent = Union[str, bytes, Iterable[bytes], AsyncIterable[bytes]]
RequestData = dict
HeaderTypes = Union[
    MutableMapping[str, str],
    Dict[str, str],
    Dict[bytes, bytes],
    Sequence[Tuple[str, str]],
    Sequence[Tuple[bytes, bytes]],
]

############################################################
# Extra, optional types and aliases
# (Available when installed with "--extras typing")
from dataclasses import dataclass

HttpUrl = str
EmailStr = str
Snowflake = int
SecretStr = str
try:
    from pydantic import HttpUrl
    from pydantic.dataclasses import dataclass  # type: ignore
except ImportError:
    pass
try:
    # Check if pydantic[email] works
    from pydantic import EmailStr as _EmailStr

    _EmailStr().validate("example@tusky.org")
    from pydantic import EmailStr

    del _EmailStr
except ImportError:
    pass
try:
    from tusky_snowflake import Snowflake
except ImportError:
    pass


############################################################
# Typing Generics
class _Kwargs(Protocol):
    def __init__(self, **kwargs):
        pass


# The type annotation for @classmethod and context managers here follows PEP 484
# https://www.python.org/dev/peps/pep-0484/#annotating-instance-and-class-methods
# An aside: I recently realized the letter "U" is used for TypeVars
# because it comes after "T" in the alphabet :P
T = TypeVar("T", bound=_Kwargs)
U = TypeVar("U", bound="BaseClient")


############################################################
# We need to differentiate between items that are not set and items that are set to None
class NotSet:
    pass


not_set: Any
not_set = NotSet()


############################################################
# Other API Responses
@dataclass
class EmptyResponse:
    pass


@dataclass
class User:
    id: Snowflake
    username: str
    email: Optional[EmailStr]
    is_active: bool
    is_superuser: bool
    is_verified: bool


# To implement the Mapping protocol, this class has the methods "keys" & "__getitem__"
# This means dict(LoginResponse) will work.
# Consequently, fastapi.encoders.jsonable_encoder will also work.
@dataclass
class LoginResponse:
    access_token: JWT
    refresh_token: JWT
    token_type: Literal["bearer"]

    def __str__(self):
        return (
            '{"access_token": "%s", "refresh_token": %s, "token_type": "bearer"}'
            % self.access_token,
            self.refresh_token,
        )

    def keys(self):
        return ["access_token", "refresh_token", "token_type"]

    def __getitem__(self, key):
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": "bearer",
        }[key]

    def __iter__(self):
        raise NotImplementedError


@dataclass
class RefreshResponse:
    access_token: JWT
    token_type: Literal["bearer"]

    def __str__(self):
        return '{"access_token": "%s", "token_type": "bearer"}' % self.access_token

    def keys(self):
        return ["access_token", "token_type"]

    def __getitem__(self, key):
        return {"access_token": self.access_token, "token_type": "bearer"}[key]

    def __iter__(self):
        raise NotImplementedError


########################################################################################
# Helper functions
########################################################################################
def create_body(*pairs: Tuple[Any, Any]) -> Dict:
    """Create body message without unset fields"""
    return {k: v for k, v in pairs if type(v) is not NotSet}


def jwt_to_auth_headers(jwt: JWT) -> Dict[str, str]:
    return {"Authorization": f"Bearer {jwt}"}


# Todo: Add documentation and documentation wrapper


########################################################################################
# Clients & end-user API
########################################################################################
class BaseClient:
    _client_type: ClientType
    _BASE_URL = "http://localhost:8007"

    def __init__(self):
        self._client = self._client_type()

    @property
    def is_closed(self) -> bool:
        return self._client.is_closed

    def close(self) -> None:
        self._client.close()

    def __enter__(self: U) -> U:
        self._client.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # httpx clients have different implementations for close & exit,
        # so we don't just call self.close()
        self._client.__exit__(exc_type, exc_val, exc_tb)


class Client(BaseClient):
    _client_type = httpx.Client

    def _request(
        self,
        method: str,
        url: HttpUrl,
        *,
        return_type: Type[T],
        content: RequestContent = None,
        data: RequestData = None,
        headers: HeaderTypes = None,
        **kwargs,
    ) -> T:
        response = self._client.request(
            method=method,
            url=self._BASE_URL + url,
            content=content,
            data=data,
            headers=headers,
            **kwargs,
        )
        response.raise_for_status()
        return return_type(**response.json())

    def register(
        self,
        username: str,
        password: SecretStr,
        email: EmailStr = not_set,
        grant_type: str = not_set,
        scope: str = not_set,
        client_secret: SecretStr = not_set,
    ) -> User:
        body = create_body(
            ("username", username),
            ("email", email),
            ("password", password),
            ("grant_type", grant_type),
            ("scope", scope),
            ("client_secret", client_secret),
        )
        return self._request(
            "post",
            "/auth/register",
            return_type=User,
            json=body,
        )

    # grant_type: str = None, scope: str = None, client_id: str = None, client_secret: SecretStr = None
    def login(
        self,
        username: str,
        password: SecretStr,
    ) -> LoginResponse:
        return self._request(
            "post",
            "/auth/jwt/login",
            return_type=LoginResponse,
            data=({"username": username, "password": password}),
        )

    def refresh(
        self,
        client_id: Union[int, str],
        refresh_token: JWT,
        scope: str = not_set,  # Todo Union[str, List[str]]
        client_secret: str = not_set,
    ) -> RefreshResponse:
        body = create_body(
            ("grant_type", "refresh_token"),
            ("client_id", str(client_id)),
            ("refresh_token", refresh_token),
            ("scope", scope),
            ("client_secret", client_secret),
        )
        return self._request(
            "post", "/auth/jwt/refresh", return_type=RefreshResponse, json=body
        )

    def revoke(self, client_id: Union[int, str], token: str) -> str:
        return self._request(
            "post", "/auth/jwt/revoke", return_type=EmptyResponse, json={"client_id": str(client_id), "token": token}
        )

    def verify(self, token: JWT) -> User:
        return self._request(
            "post", "/auth/verify", return_type=User, json={"token": token}
        )

    def get_me(self, token: JWT) -> User:
        auth_headers = jwt_to_auth_headers(token)
        return self._request("get", "/users/me", return_type=User, headers=auth_headers)

    def update_me(
        self,
        token: JWT,
        email: EmailStr = not_set,
        password: SecretStr = not_set,
        username: str = not_set,
    ):
        auth_headers = jwt_to_auth_headers(token)
        body = create_body(
            ("email", email), ("password", password), ("username", username)
        )
        return self._request(
            "patch", "/users/me", return_type=User, headers=auth_headers, json=body
        )


class AsyncClient(BaseClient):
    _client_type = httpx.AsyncClient

    async def _request(
        self,
        method: str,
        url: HttpUrl,
        *,
        return_type: Type[T],
        content: RequestContent = None,
        data: RequestData = None,
        **kwargs,
    ):
        response = await self._client.request(
            method=method,
            url=self._BASE_URL + url,
            content=content,
            data=data,
            **kwargs,
        )
        response.raise_for_status()
        return return_type(**response.json())

    async def register(
        self,
        username: str,
        password: SecretStr,
        email: EmailStr = not_set,
        grant_type: str = not_set,
        scope: str = not_set,
        client_secret: SecretStr = not_set,
    ) -> Coroutine:
        body = create_body(
            ("username", username),
            ("email", email),
            ("password", password),
            ("grant_type", grant_type),
            ("scope", scope),
            ("client_secret", client_secret),
        )
        return await self._request(
            "post",
            "/auth/register",
            return_type=User,
            json=body,
        )

    async def login(
        self,
        username: str,
        password: SecretStr,
    ) -> Coroutine:
        return await self._request(
            "post",
            "/auth/jwt/login",
            return_type=LoginResponse,
            data=({"username": username, "password": password}),
        )

    async def refresh(
        self,
        client_id: Union[int, str],
        refresh_token: JWT,
        scope: str = not_set,  # Todo Union[str, List[str]]
        client_secret: str = not_set,
    ) -> Coroutine:
        body = create_body(
            ("grant_type", "refresh_token"),
            ("client_id", str(client_id)),
            ("refresh_token", refresh_token),
            ("scope", scope),
            ("client_secret", client_secret),
        )
        return await self._request(
            "post", "/auth/jwt/refresh", return_type=RefreshResponse, json=body
        )

    async def revoke(self, client_id: Union[int, str], token: str) -> Coroutine:
        return self._request(
            "post", "/auth/jwt/revoke", return_type=EmptyResponse, json={"client_id": str(client_id), "token": token}
        )

    async def verify(self, token: JWT) -> Coroutine:
        return await self._request(
            "post", "/auth/verify", return_type=User, json=({"token": token})
        )

    async def get_me(self, token: JWT) -> Coroutine:
        auth_headers = jwt_to_auth_headers(token)
        return await self._request(
            "get", "/users/me", return_type=User, headers=auth_headers
        )

    async def update_me(
        self,
        token: JWT,
        email: EmailStr = not_set,
        password: SecretStr = not_set,
        username: str = not_set,
    ) -> Coroutine:
        auth_headers = jwt_to_auth_headers(token)
        body = create_body(
            ("email", email), ("password", password), ("username", username)
        )
        return await self._request(
            "patch", "/users/me", return_type=User, headers=auth_headers, json=body
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self: U) -> U:
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._client.__aexit__(exc_type, exc_val, exc_tb)


async def register(
    username: str,
    password: SecretStr,
    email: EmailStr = not_set,
    grant_type: str = not_set,
    scope: str = not_set,
    client_secret: SecretStr = not_set,
) -> Coroutine:
    async with AsyncClient() as c:
        return await c.register(
            username,
            email,
            password,
            grant_type=grant_type,
            scope=scope,
            client_secret=client_secret,
        )


async def login(username: str, password: SecretStr):
    async with AsyncClient() as c:
        return await c.login(username, password)


async def refresh(
    client_id: Union[int, str],
    refresh_token: JWT,
    scope: str = not_set,
    client_secret: str = not_set,
):
    async with AsyncClient() as c:
        return await c.refresh(client_id, refresh_token, scope, client_secret)


async def revoke(client_id: Union[int, str], token: str):
    with AsyncClient() as c:
        return await c.revoke(client_id, token)


async def verify(token: JWT):
    async with AsyncClient() as c:
        return await c.verify(token)


async def get_me(token: JWT):
    async with AsyncClient() as c:
        return await c.get_me(token)


async def update_me(
    token: JWT,
    email: EmailStr = not_set,
    password: SecretStr = not_set,
    username: str = not_set,
) -> Coroutine:
    async with AsyncClient() as c:
        return await c.update_me(
            token, email=email, password=password, username=username
        )
