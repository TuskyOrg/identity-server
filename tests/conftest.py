""" conftest.py is a file that pytest specifically searches for to configure tests """
import random
import string
from typing import Generator, Dict

import pytest
from fastapi.testclient import TestClient
from fastapi_users import db as fast_db, models as fast_models
from pydantic import EmailStr
from server import app, settings


########################################################################################
# utils
from server._app import UserCreate


def random_string() -> str:
    return "".join(random.choices(string.ascii_letters, k=32))


def get_user_authentication_headers(client, username: str, password: str):
    login_data = {"username": username, "password": password}
    res = client.post(f"/login/access-token", data=login_data)
    tokens = res.json()
    access_token = tokens["access_token"]
    return {"Authorization": f"Bearer {access_token}"}


########################################################################################
# fixtures

@pytest.fixture(scope="module")
def client() -> Generator:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def superuser_token_headers(client: TestClient) -> Dict[str, str]:
    return get_user_authentication_headers(
        client=client,
        username=settings.FIRST_SUPERUSER_USERNAME,
        password=settings.FIRST_SUPERUSER_PASSWORD,
    )


@pytest.fixture(scope="module")
def normal_user_token_headers(
    client: TestClient, db: fast_db.sqlalchemy.BaseUserDatabase[fast_models.UD]
) -> Dict[str, str]:
    """
    Returns a valid token for the test user.
    If the user doesn't exist, the user is first created.
    """
    password = random_string()
    user_init = UserCreate(
        username=settings.TEST_USER_USERNAME, email=settings.TEST_USER_EMAIL, password=password
    )
    user = client.post("/auth/register", user_init)
    return get_user_authentication_headers(
        client=client, username=user.username, password=password
    )
