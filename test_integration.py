# Oh well, bad tests that are difficult to run are better than no tests
# To run tests:
#   Start server (docker compose up --build) and snowflake server (https://github.com/TuskyOrg/snowflake-server)
#   Reset database
#   python test_integration.py

import client

from httpx import HTTPStatusError


def test_everything():

    with tusky_users.Client() as c:
        # Register user with name and email
        U1_NAME = "u1"
        U1_EMAIL = "u1@tusky.org"
        U1_PASS = "fake_pass"
        u1 = c.register(username=U1_NAME, email=U1_EMAIL, password=U1_PASS)
        token_from_name = c.login(U1_NAME, U1_PASS)
        u1_me_by_name = c.get_me(token_from_name.access_token)
        token_from_email = c.login(U1_EMAIL, U1_PASS)
        u1_me_by_email = c.get_me(token_from_email.access_token)
        assert u1 == u1_me_by_name == u1_me_by_email

        ################################################################################
        # Register with just username
        U2_NAME = "u2"
        U2_PASS = "u2@tusky.org"
        user = c.register(username=U2_NAME, password=U2_PASS)

        # Ensure you can't have duplicate names
        try:
            c.register(username=U1_NAME, password="som3jUNK")
            RuntimeError("Oh no! Duplicate usernames were registered to the db")
        except HTTPStatusError as err:
            pass

        ################################################################################
        # Ensure you can't have duplicate emails
        U3_OLD_NAME = "u3"
        U3_NEW_NAME = "u3_new_name"
        U3_PASSWORD = "u3password"
        try:
            c.register(username=U3_OLD_NAME, email=U1_EMAIL, password=U1_PASS)
            RuntimeError("Oh no! Duplicate emails were registered to the db")
        except HTTPStatusError:
            pass

        ################################################################################
        # Ensure user wasn't written to database on error
        u3 = c.register(username=U3_OLD_NAME, password=U3_PASSWORD)

        # Todo: Ensure users can't set themselves to be a superuser
        #
        u3_token = c.login(username=U3_OLD_NAME, password=U3_PASSWORD)
        u3_old_me = c.get_me(u3_token.access_token)
        c.update_me(u3_token.access_token, username=U3_NEW_NAME)
        u3_new_me = c.get_me(u3_token.access_token)
        assert u3_new_me.username == U3_NEW_NAME
        assert u3_old_me.id == u3_new_me.id

        ################################################################################
        # assert user 3 cannot get a new login token with the old username
        try:
            c.login(username=U3_OLD_NAME, password=U3_PASSWORD)
            RuntimeError("Oh no! A user logged in with outdated information")
        except HTTPStatusError:
            pass

        ################################################################################
        # Log in with changed password
        u3_new_token = c.login(username=U3_NEW_NAME, password=U3_PASSWORD)
        # The login endpoint should create a refresh token in the database

        ################################################################################
        # Test refresh token
        refresh_response1 = c.refresh(u3.id, u3_new_token.refresh_token)
        c.get_me(refresh_response1.access_token)
        # And a second one
        refresh_response2 = c.refresh(u3.id, u3_new_token.refresh_token)
        c.get_me(refresh_response2.access_token)

        ################################################################################
        # TODO: Assert access token can't hit endpoints requiring a new token
        # try:
        #     c.get_me(refresh_response1.access_token)
        #     raise RuntimeError("Oh no! An old access token was able to be used")
        # except HTTPStatusError:
        #     pass
        # Assert new token is still fine
        c.get_me(refresh_response2.access_token)
        # Assert old refresh token cannot be refreshed
        try:
            c.refresh(u3.id, u3_new_token.access_token)
            raise RuntimeError("Oh no! An old refresh token was able to be used")
        except HTTPStatusError:
            pass

        ################################################################################
        # Assert revoking refresh token
        c.revoke(u3.id, u3_new_token.refresh_token)
        try:
            c.refresh(u3.id, u3_new_token.refresh_token)
            raise RuntimeError("Oh no! A revoked token was able to be used")
        except HTTPStatusError:
            pass

        print(
            "Passed all the current tests. Remember, there isn't a log out button yet. "
            "Make sure to add one before hitting production."
            "\n"
            "We also lack a test asserting users can't change to superuser "
            "(aside from manually testing, which is rarely ran)"
            "\n"
            "It would also be nice to have tests that aren't as difficult to run 😛"
        )


if __name__ == "__main__":
    test_everything()
