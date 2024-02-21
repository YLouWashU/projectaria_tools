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
import functools
import glob
import json
import logging
from enum import auto, Enum, unique
from pathlib import Path
from typing import Any, Dict, Final, List, Mapping, Optional, Sequence

from transitions.core import EventData

from .base_state_machine import BaseStateMachine
from .constants import (
    CHECKING,
    CREATED,
    ENCRYPTING,
    ERROR,
    ERROR_DUPLICATE_RECORDING,
    ERROR_ENCRYPTION,
    ERROR_HEALTH_CHECK,
    ERROR_SOMETHING_ELSE,
    ERROR_STATE_MACHINE,
    HASHING,
    HEALTHCHECK,
    SUBMITTING,
    UPLOADING,
)
from .encryption import VrsEncryptor
from .hash_calculator import HashCalculator
from .health_check import is_eligible, run_health_check
from .http_helper import HttpHelper
from .request_monitor import RequestMonitor

from .types import (
    AriaRecording,
    EncryptionError,
    ModelState,
    MpsFeature,
    MpsFeatureRequest,
    MpsRequest,
    Status,
    VrsHealthCheckError,
)
from .uploader import check_if_already_uploaded, Uploader

logger = logging.getLogger(__name__)


class MultiRecordingRequest(BaseStateMachine):
    """
    MPS State Machine to run MPS on a group of aria recordings
    """

    @unique
    class States(Enum):
        CREATED = auto()
        HASH_COMPUTATION = auto()
        EXISTING_REQUESTS_CHECK = auto()
        VALIDATION = auto()
        UPLOAD = auto()
        SUBMIT = auto()
        SUCCESS = auto()
        FAILURE = auto()

    TRANSITIONS: Final[List[List[Any]]] = [
        # ["trigger", "source", "dest", "conditions"]
        ["next", "*", States.FAILURE, "has_error"],
        ["start", States.CREATED, States.HASH_COMPUTATION],
        ["next", States.HASH_COMPUTATION, States.EXISTING_REQUESTS_CHECK],
        ["next", States.EXISTING_REQUESTS_CHECK, States.VALIDATION],
        ["next", States.VALIDATION, States.UPLOAD],
        ["next", States.UPLOAD, States.SUBMIT],
        ["finish", [States.EXISTING_REQUESTS_CHECK, States.SUBMIT], States.SUCCESS],
    ]

    def __init__(
        self,
        monitor: RequestMonitor,
        http_helper: HttpHelper,
        cmd_args: argparse.Namespace,
        **kwargs,
    ):
        self._monitor: RequestMonitor = monitor
        self._http_helper: HttpHelper = http_helper
        self._cmd_args: argparse.Namespace = cmd_args
        super().__init__(
            states=self.States,
            transitions=self.TRANSITIONS,
            initial=self.States.CREATED,
            **kwargs,
        )

    async def add_new_recordings(self, input_paths: List[Path]) -> None:
        """
        Search for all aria recordings recursively in all the input paths and add them
        to the state machine
        """
        (
            encryption_key,
            key_id,
        ) = await self._http_helper.query_encryption_key()

        recordings: List[Path] = []
        for input_path in input_paths:
            if input_path.is_file():
                if input_path.suffix != ".vrs":
                    raise ValueError(f"Only .vrs file supported: {input_path}")
                recordings.append(Path(input_path))
            elif input_path.is_dir():
                for rec in glob.glob(f"{input_path}/**/*.vrs", recursive=True):
                    recordings.append(Path(rec))
            else:
                raise ValueError(f"Invalid input path: {input_path}")
        model = MultiRecordingModel(
            recordings=recordings,
            request_monitor=self._monitor,
            http_helper=self._http_helper,
            force=self._cmd_args.force,
            suffix=self._cmd_args.suffix,
            retry_failed=self._cmd_args.retry_failed,
            output_dir=self._cmd_args.output_dir,
            encryption_key=encryption_key,
            key_id=key_id,
        )

        self.add_model(model)
        logger.debug(
            f"Adding {model._recordings} to state machine {self.__class__.__name__}"
        )
        self._tasks.append(asyncio.create_task(model.start()))

        logger.debug("Done adding model")

    def fetch_current_model_states(
        self,
    ) -> Mapping[Path, Mapping[MpsFeature, ModelState]]:
        """
        Get the current state of each recording in each model
        Note: Each model contains exactly one feature but may contain one or more
        recordings attached to it
        """
        current_states = {}
        for model in self.models:
            for r in model.recordings:
                if r not in current_states:
                    current_states[r] = {}
                current_states[r][MpsFeature.MULTI_SLAM] = model.get_status(r)
        return current_states


class MultiRecordingModel:
    """
    MPS Request model for a group of aria recordings that are processed together
    """

    def __init__(
        self,
        recordings: List[Path],
        request_monitor: RequestMonitor,
        http_helper: HttpHelper,
        force: bool,
        suffix: Optional[str],
        retry_failed: bool,
        output_dir: Optional[Path],
        encryption_key: str,
        key_id: int,
    ) -> None:
        self._feature: MpsFeature = MpsFeature.MULTI_SLAM
        self._request_monitor: RequestMonitor = request_monitor
        self._http_helper: HttpHelper = http_helper
        self._force: bool = force
        self._suffix: Optional[str] = suffix
        self._retry_failed: bool = retry_failed
        self._hash_calculators: Mapping[Path, HashCalculator] = {}
        self._output_dir: Path = output_dir
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._recordings: List[AriaRecording] = []

        self._encryption_key: str = encryption_key
        self._key_id: int = key_id
        self._error_codes: Dict[Path, int] = {}

        multi_slam_mapping: Dict[str, str] = {}
        for i, rec in enumerate(recordings):
            output_path = self._output_dir / str(i)
            self._recordings.append(
                AriaRecording.create(vrs_path=rec, output_path=output_path)
            )
            multi_slam_mapping[str(rec)] = str(output_path)
        # Save the mapping between original vrs files and the output directory
        with open(self._output_dir / "multi_slam_mapping.json", "w") as fp:
            json.dump(multi_slam_mapping, fp, indent=2)

    @property
    def recordings(self) -> Sequence[Path]:
        """
        All the recordings associated with this feature request
        """
        return [r.path for r in self._recordings]

    def get_status(self, recording: Path) -> str:
        """
        The current status of the request.
        We append the progress, where applicable
        """
        if self.is_CREATED():
            return ModelState(status=CREATED)
        if self.is_HASH_COMPUTATION():
            hash_calculator = self._hash_calculators.get(recording)
            progress = hash_calculator.progress if hash_calculator else 0
            return ModelState(status=HASHING, progress=progress)
        if self.is_EXISTING_REQUESTS_CHECK():
            return ModelState(status=CHECKING)
        if self.is_VALIDATION():
            return ModelState(status=HEALTHCHECK)
        if self.is_UPLOAD():
            uploader = self._uploaders.get(recording)
            if uploader:
                return ModelState(status=UPLOADING, progress=uploader.progress)

            encryptor = self._encryptors.get(recording)
            progress = encryptor.progress if encryptor else 0
            return ModelState(status=ENCRYPTING, progress=progress)
        if self.is_SUBMIT():
            return ModelState(status=SUBMITTING)
        if self.is_SUCCESS():
            return ModelState(status="Should not be here")
        if self.is_FAILURE():
            return ModelState(
                status=ERROR,
                # If we don't have an error code, then that means that some other
                # recording failed
                error_code=str(self._error_codes.get(recording, ERROR_SOMETHING_ELSE)),
            )
        raise RuntimeError(f"Unknown state {self.state}")

    def has_error(self, event: EventData) -> bool:
        """
        Check if an error occurred during the state machine execution
        """
        logger.debug(event)
        logger.debug(f"has_error : {self._error_codes}")
        return bool(self._error_codes)

    async def on_enter_HASH_COMPUTATION(self, event: EventData) -> None:
        logger.debug(event)
        hash_calculation_tasks: List[asyncio.Task] = []
        for rec in self._recordings:
            self._hash_calculators[rec.path] = HashCalculator(rec.path, self._suffix)
            hash_calculation_tasks.append(
                asyncio.create_task(self._hash_calculators[rec.path].run())
            )

            def _assign_hash(r: AriaRecording, t: asyncio.Future) -> None:
                r.file_hash = t.result()

            hash_calculation_tasks[-1].add_done_callback(
                functools.partial(_assign_hash, rec)
            )
        await asyncio.gather(*hash_calculation_tasks)
        file_hashes: List[str] = [rec.file_hash for rec in self._recordings]
        for fh in file_hashes:
            if file_hashes.count(fh) > 1:
                self._error_codes[rec.path] = ERROR_DUPLICATE_RECORDING
        await self.next()
        self._hash_calculators = {}  # TODO: use before/after callback to clean up

    async def on_enter_EXISTING_REQUESTS_CHECK(self, event: EventData) -> None:
        logger.debug(event)
        if not self._force:
            mps_feature_request: Optional[
                MpsFeatureRequest
            ] = await self._http_helper.query_mps_requested_feature_by_file_hash_set(
                list({r.file_hash for r in self._recordings})
            )
            if mps_feature_request and mps_feature_request.status != Status.FAILED:
                logger.info(
                    "Found an existing feature request with the same file hash. Skipping submission."
                )
                await self._request_monitor.track_feature_request(
                    recordings=self._recordings,
                    feature_request=mps_feature_request,
                )
                await self.finish()
                return
        await self.next()

    async def on_enter_VALIDATION(self, event: EventData) -> None:
        logger.debug(event)

        async def _health_check(rec: AriaRecording) -> None:
            if not self._force and rec.health_check_path.is_file():
                logger.info(
                    f"Health check output already exists at {rec.health_check_path}, skipping VrsHealthCheck"
                )
            else:
                await run_health_check(rec.path, rec.health_check_path)
            if not rec.health_check_path.is_file():
                logger.error("Failed to run VrsHealthCheck for {rec.path}")
                self._error_codes[rec.path] = ERROR_HEALTH_CHECK
                raise VrsHealthCheckError()

            if not is_eligible(MpsFeature.MULTI_SLAM, rec):
                logger.error(f"{rec.path} is not eligible for multi-slam")
                self._error_codes[rec.path] = ERROR_HEALTH_CHECK
                raise VrsHealthCheckError()

        health_check_tasks: List[asyncio.Task] = []
        for rec in self._recordings:
            health_check_tasks.append(asyncio.create_task(_health_check(rec)))
        try:
            await asyncio.gather(*health_check_tasks)
        except VrsHealthCheckError:
            # Should be handled by error handling with next()
            ## Note that the pending tasks continue to run in the background
            pass
        await self.next()

    async def on_enter_UPLOAD(self, event: EventData) -> None:
        logger.debug(event)

        async def _encrypt_and_upload(rec: AriaRecording) -> None:
            """
            We combine encryption and upload into a single state here. This is to avoid
            waiting for encryption to finish on all files before starting the uploads.
            With this, a file upload will start immediately after encryption has finished.
            """
            recording_fbid: Optional[int] = await check_if_already_uploaded(
                rec.file_hash, self._http_helper
            )
            if recording_fbid:
                rec.fbid = recording_fbid
                logger.warning(
                    f"Found an existing recording with id {recording_fbid} for {rec.path}"
                )
            else:
                if rec.encrypted_path.is_file():
                    logger.warning(
                        f"Encrypted file already exists at {rec.encrypted_path}, skipping encryption"
                    )
                else:
                    self._encryptors[rec.path] = VrsEncryptor(
                        rec.path,
                        rec.encrypted_path,
                        self._encryption_key,
                        self._key_id,
                    )
                    await self._encryptors[rec.path].run()

                if not rec.encrypted_path.is_file():
                    self._error_codes[rec.path] = ERROR_ENCRYPTION
                    raise EncryptionError()

                self._uploaders[rec.path] = Uploader(
                    rec.encrypted_path, rec.file_hash, self._http_helper
                )
                if rec.path in self._encryptors:
                    self._encryptors.pop(rec.path)
                rec.fbid = await self._uploaders[rec.path].run()

        self._uploaders: Mapping[Path, Uploader] = {}
        self._encryptors: Mapping[Path, VrsEncryptor] = {}
        upload_tasks: List[asyncio.Task] = [
            asyncio.create_task(_encrypt_and_upload(rec)) for rec in self._recordings
        ]

        #
        try:
            await asyncio.gather(*upload_tasks)
        except EncryptionError:
            # Should be handled by error handling with next()
            ## Note that the pending tasks continue to run in the background
            pass

        await self.next()
        self._uploaders = {}  # TODO: Do this in before/after callback

    async def on_enter_SUBMIT(self, event: EventData) -> None:
        logger.debug(event)
        assert all(rec.fbid for rec in self._recordings)
        mps_request: MpsRequest = await self._http_helper.submit_request(
            name=f"{self._feature.value} request",
            recording_ids=[rec.fbid for rec in self._recordings],
            features=[self._feature.value],  # TODO: match names with server side
        )
        await self._request_monitor.track_feature_request(
            recordings=self._recordings,
            feature_request=mps_request.features[self._feature],
        )

        await self.finish()

    async def on_enter_SUCCESS(self, event: EventData) -> None:
        logger.debug(event)

    async def on_enter_FAILURE(self, event: EventData) -> None:
        logger.critical(event)
        logger.critical(
            f"Error : {event.error}, args: {event.args}, kwargs: {event.kwargs}"
        )

    async def on_exception(self, event: EventData) -> None:
        """
        This method is called whenever an exception occurs during execution of the
        state machine.
        """
        logger.error(f"Exception when processing {event}")
        # For future reference, here's how to log the exception without raising
        # it:
        # logger.error("".join(traceback.format_tb(event.error.__traceback__)))
        #
        # In order for the exception to be logged properly, we need to re-raise
        # the exception and then log it
        try:
            raise event.error
        except Exception as e:
            logger.exception(e)

        self._error_codes = {str(r.path): ERROR_STATE_MACHINE for r in self._recordings}

        await self.next()
