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

import argparse
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import aiohttp

from .authentication import authenticate, logout
from .common import Config
from .constants import DEFAULT, LOG_DIR
from .http_helper import HttpHelper
from .multi_recording_request import MultiRecordingRequest
from .request_monitor import RequestMonitor
from .single_recording_request import SingleRecordingRequest
from .status_display import StatusDisplay
from .types import MpsFeature

logger = logging.getLogger(__name__)

_SINGLE_COMMAND: str = "single"
_MULTI_COMMAND: str = "multi"


async def _run_async():
    """Main async entry point for the CLI"""
    asyncio.current_task().set_name("main")
    args = _parse_args()
    log_path: Path = _configure_logging(args)
    # The --logout parameter on cmd line will be overridden by the user input during
    # authentication, if they select to save the auth token, when manually entering
    # username and password.
    enable_logout: bool = args.logout

    async with aiohttp.ClientSession(raise_for_status=True) as http_session:
        http_helper: HttpHelper = HttpHelper(http_session)
        username, enable_logout = await authenticate(
            http_helper, args.username, args.password, enable_logout
        )

        # Create MPS Request Monitor and MPS Requestor
        request_monitor = RequestMonitor(http_helper)
        if args.mode == _MULTI_COMMAND:
            requestor: MultiRecordingRequest = MultiRecordingRequest(
                monitor=request_monitor,
                http_helper=http_helper,
                cmd_args=args,
            )
        elif args.mode == _SINGLE_COMMAND:
            requestor: SingleRecordingRequest = SingleRecordingRequest(
                monitor=request_monitor,
                http_helper=http_helper,
                cmd_args=args,
            )
        else:
            raise ValueError(f"Unknown mode {args.mode}")

        # Add new VRS files to be processed
        await requestor.add_new_recordings(args.input)

        display: Optional[StatusDisplay] = None
        # Do not show the table in verbose mode. The continuous stream of verbose output
        # makes it hard to read
        if not args.verbose:
            display: StatusDisplay = StatusDisplay(
                [requestor, request_monitor], username=username, log_path=log_path
            )
            display_task = asyncio.create_task(display.refresh())
        # Wait for all the requests to be submitted
        await asyncio.gather(*requestor.tasks)

        # Wait for all the requests to finish
        await asyncio.gather(*request_monitor.tasks)

        if display:  # Stop the display
            await asyncio.sleep(2)
            display.stop()
            await display_task
        if enable_logout:
            await logout(http_helper)


def _add_common_args(parser: argparse.ArgumentParser):
    """
    Add common arguments to the parser
    """
    parser.add_argument(
        "-i",
        "--input",
        help="Path to the input VRS file or directory containing VRS files",
        action="append",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--retry-failed",
        help="Retry failed requests",
        action="store_true",
        dest="retry_failed",
    )
    parser.add_argument(
        "--force",
        help="Force compute everything",
        action="store_true",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Verbose output",
        action="store_true",
    )
    parser.add_argument(
        "-u",
        "--username",
        help="Username to use when connecting to MPS. This can be an email address, or a username",
        type=str,
    )
    parser.add_argument(
        "-p",
        "--password",
        help="Password to use when connecting to MPS.",
        type=str,
    )
    parser.add_argument(
        "--logout",
        help="Log out from MPS after processing the request. The cached auth token will be removed.",
        action="store_true",
    )
    # For debugging only to re-upload the same file by appending the suffix to the
    # file hash
    parser.add_argument("-s", "--suffix", help=argparse.SUPPRESS, type=str)


def _parse_args() -> argparse.Namespace:
    """
    Helpers to parse command line arguments
    """
    parser = argparse.ArgumentParser(description="Aria MPS Command Line Interface")

    # Define the subparsers
    subparsers = parser.add_subparsers(
        dest="mode", help="sub-command help", required=True
    )
    # Define the single_sequence subcommand
    parser_single = subparsers.add_parser(
        _SINGLE_COMMAND,
        help="Single sequence MPS. MPS will process each VRS file separately",
    )
    _add_common_args(parser_single)
    parser_single.add_argument(
        "--features",
        help="MP feature(s) to generate",
        nargs="+",
        choices=[MpsFeature.EYE_GAZE.value, MpsFeature.SLAM.value],
        type=MpsFeature,
        default=[MpsFeature.EYE_GAZE, MpsFeature.SLAM],
    )
    # Define the multi_sequence subcommand
    parser_multi = subparsers.add_parser(
        _MULTI_COMMAND,
        help="Multi sequence MPS. MPS will process the group of VRS files together to produce a trajectories in a common frame of reference.",
    )
    _add_common_args(parser_multi)
    parser_multi.add_argument(
        "-o",
        "--output",
        help="Output directory where the results will be stored",
        dest="output_dir",
        type=Path,
        required=True,
    )

    return parser.parse_args()


def _configure_logging(args) -> Path:
    """
    Setup logging to file and remove default logger unless verbose mode is enabled
    """
    config = Config.get()
    log_dir = Path(config.get(DEFAULT, LOG_DIR))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file: Path = log_dir / f"{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.log"
    handlers: List[logging.StreamHandler] = [logging.FileHandler(log_file)]
    if args.verbose:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        handlers=handlers,
        level=logging.DEBUG,
        format="%(asctime)s [%(process)d] [%(levelname)s] [%(filename)s:%(lineno)d] - %(message)s",
    )

    logger.info(f"log file : {log_file}")
    return log_file


def run():
    """Synchronous entry point for the CLI"""
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_run_async())
