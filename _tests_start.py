import logging
from unittest.mock import patch

import tusky_snowflake

# tenacity is a library to retry code until it succeeds
from tenacity import after_log, before_log, retry, stop_after_attempt, wait_fixed

from server import initdb

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

max_tries = 8
wait_seconds = 1


@retry(
    stop=stop_after_attempt(max_tries),
    wait=wait_fixed(wait_seconds),
    before=before_log(logger, logging.INFO),
    after=after_log(logger, logging.WARN),
)
@patch(
    "server._app.synchronous_get_snowflake",
    tusky_snowflake.mock.new_snowflake_service().synchronous_get_snowflake,
)
def wait_for_database_to_be_setup() -> None:
    try:
        initdb()
        return
    except Exception as e:
        logger.error(e)
        raise e


if __name__ == "__main__":
    logger.info("Initializing service")
    wait_for_database_to_be_setup()
    logger.info("Service finished initializing")
