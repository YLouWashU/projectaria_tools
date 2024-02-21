# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import concurrent
import functools
import logging
import platform
import zipfile
from configparser import ConfigParser
from datetime import datetime, timedelta
from functools import wraps
from typing import (
    Any,
    Callable,
    Dict,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
)

import aiohttp


logger = logging.getLogger(__name__)

from .constants import (
    BACKOFF,
    CHUNK_SIZE,
    CONCURRENT_DOWNLOADS,
    CONCURRENT_ENCRYPTIONS,
    CONCURRENT_HASHES,
    CONCURRENT_HEALTH_CHECKS,
    CONCURRENT_UPLOADS,
    CONFIG_FILE,
    DEFAULT,
    DELETE_ENCRYPTED_FILES,
    DELETE_ZIP,
    DOWNLOAD,
    ENCRYPTION,
    GRAPHQL,
    HASH,
    HEALTH_CHECK,
    INTERVAL,
    LOG_DIR,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    RETRIES,
    SMOOTHING_WINDOW_SIZE,
    STATUS_CHECK_INTERVAL,
    TARGET_CHUNK_UPLOAD_SECS,
    UPLOAD,
)


T = TypeVar("T")


class PeriodicLogger:
    """
    Logging every X seconds
    """

    def __init__(self, delta: Optional[timedelta] = None):
        self._delta: timedelta = delta or timedelta(seconds=1)
        self._prev_logtime: Optional[datetime] = None

    def log(self, msg: str, func: Callable = logger.info, override: bool = False):
        now = datetime.now()
        if (
            override
            or not self._prev_logtime
            or now - self._prev_logtime >= self._delta
        ):
            func(msg)
            self._prev_logtime = now


class CustomAdapter(logging.LoggerAdapter):
    """Custom logging adapter to print the contextual information like vrs file"""

    def process(
        self, msg: Any, kwargs: MutableMapping[str, str]
    ) -> Tuple[str, MutableMapping[str, str]]:
        suffix = " ".join([f"[{k}:{v}]" for k, v in self.extra.items()])
        return " ".join([str(suffix), str(msg)]), kwargs


async def to_proc(func: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
    """
    Use this for synchronous cpu bound tasks
    Main functionality is to maintain context when offloading to OS threads.
    """
    loop = asyncio.get_running_loop()
    func_call = functools.partial(func, *args, **kwargs)
    with concurrent.futures.ProcessPoolExecutor() as pool:
        return await loop.run_in_executor(pool, func_call)


def unzip(zip_filepath, dest_dir) -> None:
    """
    Unzips a zip file into a destination directory
    """
    with zipfile.ZipFile(zip_filepath, "r") as zip_ref:
        zip_ref.extractall(dest_dir)


def retry(
    exceptions: Optional[Sequence[Exception]] = None,
    error_codes: Optional[Sequence[int]] = None,
    retries: int = 3,
    interval: int = 1,
    backoff: float = 1.5,
):
    """
    Decorator for retrying functions up to `retries` retries if exceptions are thrown.
    Does exponential backoff between retries.
    ClientResponseError from aiohttp is treated special and will only be retried if
    the status code is in `error_codes`.
    At least one of `exceptions` or `error_codes` must be provided.

    Args:
        exceptions: List of exceptions to catch
        error_codes: List of HTTP status codes to catch
        retries: Number of times to retry
        interval: Interval between retries in seconds
        backoff: Backoff multiplier

    Usage:
    @retry(exceptions=[ValueError, TypeError], retries=5, interval=2, backoff=2)
    async def my_async_function():
        # code that might raise an exception

    """
    if not exceptions and not error_codes:
        raise ValueError(
            "At least one of `exceptions` or `error_codes` must be provided."
        )
    exceptions = exceptions or []
    if error_codes and aiohttp.ClientResponseError not in exceptions:
        exceptions.append(aiohttp.ClientResponseError)

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            attempts = 0
            while True:
                try:
                    return await func(*args, **kwargs)
                except tuple(exceptions) as e:
                    if (
                        isinstance(e, aiohttp.ClientResponseError)
                        and error_codes
                        and e.status not in error_codes
                    ):
                        logger.exception(e)
                        raise e from e
                    if attempts > retries:
                        logger.error(f"Maximum number of retries reached ({retries}).")
                        raise e from e
                    logger.warning(f"Exception encountered: {e}")
                    sleep_time = interval * (backoff ** (attempts))
                    attempts += 1
                    logger.warning(
                        f"Retrying attempt {attempts}/{retries+1} in {sleep_time} seconds..."
                    )
                    await asyncio.sleep(sleep_time)

        return wrapper

    return decorator


def get_pretty_size(num_bytes: int, suffix="B"):
    """
    Returns a human readable size string
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if num_bytes < factor:
            return f"{num_bytes:.2f} {unit}{suffix}"
        num_bytes /= factor


class Config(ConfigParser):
    """
    Simple class to access the config object
    We use a singleton pattern here so we can have one instance of the config object
    across all modules
    The actual config file is located at ~/.projectaria/mps.ini
    We leverage the ConfigParser library to parse the config file
    If the config file does not exist, we create it with default values
    Users can then overwrite the values by editing the config file directly
    """

    _config = None

    @staticmethod
    def get() -> "Config":
        """
        Get the config object
        Loads the config from ~/.projectaria/mps.ini. if it doesn't exist, creates it
        with default values
        """
        if Config._config is None:
            Config._config = ConfigParser(inline_comment_prefixes="#")

            if not CONFIG_FILE.is_file():
                concurrent_encryptions: str = "10 # Maximum number of recordings that will be encrypted concurrently"
                if platform.system() == "Darwin":  # MacOS
                    concurrent_encryptions = "1 # Maximum number of recordings that will be encrypted concurrently. This value should be set to 1 on MacOS due to an issue with multi-processing"
                _DEFAULT_CONFIG: Dict[str, Any] = {
                    UPLOAD: {
                        BACKOFF: "1.5 # Backoff factor for retries",
                        CONCURRENT_UPLOADS: "4 # Maximum number of concurrent uploads",
                        INTERVAL: "20 # Interval between runs",
                        MAX_CHUNK_SIZE: "104857600 # 100 * 2**20 (100 MB)",
                        MIN_CHUNK_SIZE: "5242880 # 5 * 2**20 (5MB)",
                        RETRIES: "10 # Number of times to retry a failed upload",
                        SMOOTHING_WINDOW_SIZE: "10 # Size of the smoothing window",
                        TARGET_CHUNK_UPLOAD_SECS: "3 # Target duration to upload a chunk",
                    },
                    DOWNLOAD: {
                        BACKOFF: "1.5 # Backoff factor for retries",
                        CHUNK_SIZE: "10485760 # 10 * 2**20 (10MB)",
                        CONCURRENT_DOWNLOADS: "10 # Maximum number of concurrent downloads",
                        DELETE_ZIP: "true # Delete zip files after extracting",
                        INTERVAL: "20 # Interval between runs",
                        RETRIES: "10 # Number of times to retry a failed upload",
                    },
                    GRAPHQL: {
                        BACKOFF: "1.5 # Backoff factor for retries",
                        INTERVAL: "4 # Interval between runs",
                        RETRIES: "3 # Number of times to retry a failed upload",
                    },
                    HASH: {
                        CONCURRENT_HASHES: "4 # Maximum number of recordings whose hashes will be calculated concurrently",
                        CHUNK_SIZE: "10485760 # 10 * 2**20 (10MB)",
                    },
                    DEFAULT: {
                        LOG_DIR: "/tmp/logs/projectaria/mps/ # Path to log directory",
                        STATUS_CHECK_INTERVAL: "30 # Status check interval in seconds",
                    },
                    ENCRYPTION: {
                        CHUNK_SIZE: "52428800 # 50 * 2**20 (50MB)",
                        CONCURRENT_ENCRYPTIONS: concurrent_encryptions,
                        DELETE_ENCRYPTED_FILES: "true # Delete encrypted files after upload is done",
                    },
                    HEALTH_CHECK: {
                        CONCURRENT_HEALTH_CHECKS: "2  # Maximum number of checks that can run concurrently",
                    },
                }

                c = ConfigParser()
                c.read_dict(_DEFAULT_CONFIG)
                CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
                with CONFIG_FILE.open("w") as fd:
                    c.write(fd)
            Config._config.read(CONFIG_FILE)
            logger.info(f"Loaded config file {CONFIG_FILE}")
        return Config._config
