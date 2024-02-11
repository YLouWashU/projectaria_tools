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

import base64
import json
import logging
import sys
import time
from http import HTTPStatus
from typing import Any, Final, Mapping, Optional, Tuple

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from .common import retry
from .constants import AUTH_TOKEN_FILE
from .http_helper import http_post, HttpHelper

logger = logging.getLogger(__name__)

# OAuth FRL|App ID| Client Token
_CLIENT_TOKEN: Final[str] = "FRL|844405224048903|ed1d75011c9a461b1f6c83c91f1fecb9"
_DOC_ID_GET_HORIZON_PROFILE_TOKEN: int = 24299011599746673
_URL_ACCOUNTS_LOGIN: str = "https://meta.graph.meta.com/accounts_login"
_URL_ACCOUNTS_LOGOUT: str = "https://graph.oculus.com/logout"
_URL_META_GQL: str = "https://meta.graph.meta.com/graphql"
_URL_ENCRYPTION_KEY: str = "https://meta.graph.meta.com/passwords_encryption?version=2"


class AuthenticationError(RuntimeError):
    """
    Raised when authentication fails
    """

    pass


async def authenticate(
    http_helper: HttpHelper,
    username: Optional[str],
    password: Optional[str],
    enable_logout: bool,
) -> Tuple[str, bool]:
    """
    1. If username and password are provided, then log in using them
    2. If no username and password are provided, but there is a valid token in
        ~/.projectaria/auth_token, then use that token.
    3. If none of the above are true, then prompt the user for their credentials

    Rules for token saving:
    If `--logout` was passed, then we disable token saving, by default. This can be
    overridden by the user when they provide a username and password on prompt.

    Args:
        http_helper (HttpHelper): The http helper to use for requests
        username (Optional[str]): Username to login with
        password (Optional[str]): Password to login with
        enable_logout (bool): Whether to logout at the end before exiting the cli.
            If true, then the token will not be saved, unless the user selected (y) to
            save the token, while providing credentials on prompt.
    Returns:
        str: The logged in user's alias
        bool: Should the user be logged out
    """
    if bool(username) ^ bool(password):
        raise ValueError("Either username or password is empty")

    # we only save the token if the user didn't want to logout
    save_token: bool = enable_logout
    if username and password:
        logger.debug(f"Logging in user {username}")
        token = await _login(http_helper, _get_email(username), password)
    elif token := _read_token():
        logger.debug(f"token read from {AUTH_TOKEN_FILE}")
        save_token = False
    elif sys.stdin.isatty():
        logger.debug("Interactive mode detected.")
        token, save_token = await _login_via_user_input(http_helper)
        # if user selected to save token, we disable logout
        enable_logout = not save_token
    else:
        raise AuthenticationError(
            "No authentication token found. Please provide username and password or run this script from an interactive shell."
        )
    http_helper.set_token(token)
    try:
        alias: str = await http_helper.query_me()
        logger.info(f"Username is {alias}")
        if save_token:
            logger.info("New token created. Saving it locally")
            _cache_token(token)
        return alias, enable_logout
    except Exception as e:
        logger.exception(f"Authentication failed. Error: {e}")
        logger.warning("Removing cached token")
        AUTH_TOKEN_FILE.unlink(missing_ok=True)
        raise AuthenticationError(f"Login failed: {e}") from e


@retry(
    error_codes=[
        HTTPStatus.REQUEST_TIMEOUT,
        HTTPStatus.SERVICE_UNAVAILABLE,
        HTTPStatus.BAD_REQUEST,
    ],
)
async def logout(http_helper: HttpHelper) -> None:
    """
    Log out the current user.
    """
    logger.info("Logging out...")
    await http_helper.post(url=_URL_ACCOUNTS_LOGOUT)
    logger.success("Logged out successfully")
    logger.warning("Removing cached token")
    AUTH_TOKEN_FILE.unlink(missing_ok=True)


async def _login_via_user_input(http_helper: HttpHelper) -> Tuple[str, bool]:
    """
    Log in via user input
    3 tries. If fails, wait 1 second before trying again.
    """
    from rich.console import Console
    from rich.prompt import Confirm, Prompt

    console = Console()
    console.print(
        "\n\nWelcome to [b]Aria Machine Perception Service[/b]. Please login to continue.\n"
    )

    token = None
    while not token:
        username = Prompt.ask("[i]Username[/i]")
        password = Prompt.ask("[i]Password[/i]", password=True)
        try:
            token = await _login(http_helper, _get_email(username), password)
            save = Confirm.ask(
                "[green]Login success!![/green] Do you want to save your login token on this computer for future use?",
                default=True,
            )
            return token, save
        except Exception as e:
            console.print(f"Failed to login. Error: {e}", style="red")
            time.sleep(1)


def _get_email(username: str) -> str:
    """
    Converts the username to email format if necessary.
    This function is needed because academic partner accounts are provisioned by us and
    they all have tfbnw.net domain. When logging in to the mobile CA, they are used to
    only entering the username without the @tfbnw.net suffix. However, we need the full
    email address to authenticate
    """
    _DOMAIN: str = "tfbnw.net"
    if username.lower().endswith(f"@{_DOMAIN}"):
        return username
    if username.count("@") >= 1:
        raise ValueError(
            f"Invalid email address: {username}. Expected format: <username>@tfbnw.net"
        )
    return f"{username}@{_DOMAIN}"


def _cache_token(token: str) -> None:
    """
    Cache the token locally
    """
    AUTH_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    with AUTH_TOKEN_FILE.open("w") as f:
        f.write(token)


def _read_token() -> Optional[str]:
    """
    Reads the token from the local disk if present
    """
    if AUTH_TOKEN_FILE.is_file():
        with AUTH_TOKEN_FILE.open("r") as f:
            return f.read().strip()
    return None


async def _login(http_helper: HttpHelper, username: str, password: str) -> str:
    """
    Authenticate using the provided credentials and returns the authentication token
    The login is done in 2 steps:
    1. Login using Meta account and get the access token
    2. Use the access token to get the profile scoped access token
    Args:
        http_helper: HTTP Helper object
        username: Username
        password: Password
    Returns:
        Authentication token
    """
    ## Step 1 : Login using Meta account
    response: Mapping[str, Any] = {}
    # 1.1 Get public key
    response = await http_post(
        http_helper.session,
        url=_URL_ENCRYPTION_KEY,
        auth_token=_CLIENT_TOKEN,
    )
    if "key_id" not in response or "public_key" not in response:
        raise AuthenticationError(
            f"Getting public key failed with response '{json.dumps(response, indent=2)}'"
        )

    # 1.2 Encrypt password
    encrypted_password: bytearray = _encrypt_password(
        key_id=response["key_id"],
        pub_key=response["public_key"],
        raw_password=password,
    )

    # 1.3 Login
    response = await http_post(
        http_helper.session,
        url=_URL_ACCOUNTS_LOGIN,
        auth_token=_CLIENT_TOKEN,
        json={
            "contact_point": username,
            "password": encrypted_password,
        },
    )
    if "access_token" not in response:
        raise AuthenticationError(
            f"Login failed with response '{json.dumps(response, indent=2)}"
        )
    logger.debug("Got meta account access token")
    user_access_token = response["access_token"]

    # Step 2 : Get Horizon profile scoped access token
    response = await http_post(
        http_helper.session,
        url=_URL_META_GQL,
        json={"doc_id": _DOC_ID_GET_HORIZON_PROFILE_TOKEN},
        auth_token=user_access_token,
    )

    try:
        profile_access_token = response["data"]["xfr_create_profile_token"][
            "profile_tokens"
        ][0]["access_token"]
    except KeyError as e:
        raise AuthenticationError(
            f"Getting profile scoped access token failed with response '{response}'"
        ) from e

    logger.debug("Got profile scoped access token")
    return profile_access_token


def _encrypt_password(key_id: int, pub_key: str, raw_password: str) -> str:
    """Encrypts the password using the public key

    Args:
        key_id: The key id used to identify the key
        pub_key: The public key used to encrypt the password
        raw_password: The password to encrypt

    Returns:
        The encrypted password in the format expected by the auth service
    """
    version_byte: int = 1
    encrypted_data: bytearray = bytearray([version_byte, key_id])
    iv = get_random_bytes(12)
    encrypted_data.extend(iv)

    # Generate a random symmetric key and encrypt it using the public key
    symmetric_key = get_random_bytes(32)  # for AES-256
    encrypted_key = PKCS1_v1_5.new(RSA.import_key(pub_key)).encrypt(symmetric_key)
    # Write encrypted key length (256 bytes) in little endian
    encrypted_data.extend(len(encrypted_key).to_bytes(2, byteorder="little"))
    # Write encrypted key
    encrypted_data.extend(encrypted_key)

    # Initialize a cipher with the symmetric key
    cipher = AES.new(symmetric_key, AES.MODE_GCM, iv)
    aad = str(int(time.time()))
    cipher.update(aad.encode())
    cipher_text, tag = cipher.encrypt_and_digest(raw_password.encode())
    encrypted_data.extend(tag)
    encrypted_data.extend(cipher_text)
    return f"#PWD_ENC:2:{aad}:{base64.urlsafe_b64encode(encrypted_data).decode()}"
