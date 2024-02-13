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

from http import HTTPStatus
from pathlib import Path
from typing import Final, Sequence

CONFIG_DIR: Final[Path] = Path.home().joinpath(".projectaria")
CONFIG_FILE: Final[Path] = CONFIG_DIR.joinpath("mps.ini")
AUTH_TOKEN_FILE: Final[Path] = CONFIG_DIR.joinpath("auth_token")

# Constants related to .ini configuration file
## SECTIONS
DEFAULT: Final[str] = "DEFAULT"
UPLOAD: Final[str] = "UPLOAD"
DOWNLOAD: Final[str] = "DOWNLOAD"
ENCRYPTION: Final[str] = "ENCRYPTION"
GRAPHQL: Final[str] = "GRAPHQL"
HASH: Final[str] = "HASH"

## Keys
BACKOFF: Final[str] = "backoff"
CHUNK_SIZE: Final[str] = "chunk_size"
CONCURRENT_DOWNLOADS: Final[str] = "concurrent_downloads"
CONCURRENT_ENCRYPTIONS: Final[str] = "concurrent_encryptions"
CONCURRENT_HASHES: Final[str] = "concurrent_hashes"
CONCURRENT_UPLOADS: Final[str] = "concurrent_uploads"
DELETE_ENCRYPTED_FILES: Final[str] = "delete_encrypted_files"
DELETE_ZIP: Final[str] = "delete_zip"
ERROR_CODES: Final[str] = "error_codes"
INTERVAL: Final[str] = "interval"
LOG_DIR: Final[str] = "log_dir"
MAX_CHUNK_SIZE: Final[str] = "max_chunk_size"
MIN_CHUNK_SIZE: Final[str] = "min_chunk_size"
RETRIES: Final[str] = "retries"
SMOOTHING_WINDOW_SIZE: Final[str] = "smoothing_window_size"
STATUS_CHECK_INTERVAL: Final[str] = "status_check_interval"
TARGET_CHUNK_UPLOAD_SECS: Final[str] = "target_chunk_upload_secs"
UPLOAD_TIMEOUT_SECS: Final[str] = "upload_timeout_secs"


# Common http status codes that should be retried
HTTP_RETRY_CODES: Final[Sequence[int]] = [
    HTTPStatus.BAD_GATEWAY,
    HTTPStatus.BAD_REQUEST,
    HTTPStatus.INTERNAL_SERVER_ERROR,
    HTTPStatus.PRECONDITION_FAILED,
    HTTPStatus.REQUEST_TIMEOUT,
    HTTPStatus.SERVICE_UNAVAILABLE,
    HTTPStatus.TOO_MANY_REQUESTS,
]

# Status display
CREATED: Final[str] = "Created"
HASHING: Final[str] = "Hashing"
CHECKING: Final[str] = "Checking"
DOWNLOADING: Final[str] = "Downloading"
HEALTHCHECK: Final[str] = "HealthCheck"
UPLOADING: Final[str] = "Uploading"
ENCRYPTING: Final[str] = "Encrypting"
SCHEDULED: Final[str] = "Scheduled"
SUBMITTING: Final[str] = "Submitting"
SUCCESS: Final[str] = "Success"
ERROR: Final[str] = "Error"

# Error Codes
# This means something else failed so the execution was stopped
ERROR_SOMETHING_ELSE: int = 100
# An unknown exception was thrown while executing the state machine
ERROR_STATE_MACHINE: int = 101
ERROR_HEALTH_CHECK: int = 102
ERROR_DUPLICATE_RECORDING: int = 103
ERROR_ENCRYPTION: int = 104
