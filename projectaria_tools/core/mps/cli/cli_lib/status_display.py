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
import copy
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Set

import aiofiles
from rich import box
from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table

from .base_state_machine import BaseStateMachine
from .common import get_pretty_size
from .constants import (
    DOWNLOADING,
    ENCRYPTING,
    ERROR,
    HASHING,
    SCHEDULED,
    SUCCESS,
    UPLOADING,
)
from .types import ModelState, MpsFeature

logger = logging.getLogger(__name__)


class StatusDisplay:
    """
    Display status of each recording
    """

    def __init__(
        self, state_machines: Sequence[BaseStateMachine], username: str, log_path: Path
    ) -> None:
        self._state_machines = state_machines
        self._stop_event: asyncio.Event = asyncio.Event()
        self._username = username
        self._progress_bars: Mapping[Path, Dict[MpsFeature, ModelState]] = {}
        self._start_time: datetime = datetime.now()
        self._log_path = log_path

    def _refresh(self) -> Mapping[Path, Dict[MpsFeature, ModelState]]:
        """
        Refresh the status of all recordings
        """
        current_states: Mapping[Path, Dict[MpsFeature, ModelState]] = {}
        for sm in self._state_machines:
            sm_states = sm.fetch_current_model_states()
            # Merge the states from new state machines. The state from the new state
            # machine takes precedence over the current state
            current_states = {
                rec: {**current_states.get(rec, {}), **sm_states.get(rec, {})}
                for rec in set(current_states) | set(sm_states)
            }

        return current_states

    def stop(self) -> None:
        """
        Signal the display to stop
        """
        self._stop_event.set()

    async def refresh(self) -> None:
        """
        Display current state
        """
        layout = Layout(
            name="root",
        )
        layout.split(
            Layout(name="header", size=9),
            Layout(name="status_table"),
            Layout(name="footer", size=3),
        )
        layout["header"].split(
            Layout(name="title", size=3),
            Layout(name="header_top", size=1),
            Layout(name="header_bottom"),
        )
        layout["title"].update(Markdown("# ARIA MACHINE PERCEPTION SERVICE"))
        layout["header_top"].split_row(
            Layout(name="time_elapsed"), Layout(name="username")
        )
        layout["username"].update(
            Panel(
                "",
                title=f"Username: [bold][cyan]{self._username}",
                title_align="right",
                box=box.MINIMAL,
            )
        )
        header_bottom = Group(
            Panel(
                "",
                title="[i]EXPECTED STAGES",
                subtitle="[magenta]Hashing ->  HealthCheck  ->  Encryption  ->  Upload  ->  Scheduled  -> Processing  ->  Download Results  ->  Success",
                box=box.MINIMAL,
            ),
            Rule("", style="grey153"),
        )
        layout["header_bottom"].update(header_bottom)
        layout["footer"].update(
            Group(
                Rule(style="grey153"),
                Panel(
                    "",
                    title=f":scroll: Log: [bold][cyan]{self._log_path}",
                    title_align="left",
                    box=box.MINIMAL,
                ),
            )
        )

        try:
            with Live(layout) as live:
                while not self._stop_event.is_set():
                    feature_statuses = self._refresh()
                    features = sorted(_get_all_features(feature_statuses))
                    vrs_paths = sorted(feature_statuses.keys())
                    table = Table(
                        title="[b]MPS REQUESTS",
                        expand=True,
                        box=box.SQUARE_DOUBLE_HEAD,
                        style="grey37",
                    )
                    table.add_column("ID")
                    table.add_column("RECORDING", overflow="fold")
                    table.add_column("FILE SIZE", justify="right")
                    for feature in features:
                        table.add_column(feature.value.upper())
                    for i, vrs_path in enumerate(vrs_paths, 1):
                        feature_status = feature_statuses[vrs_path]
                        table.add_row(
                            str(i),
                            str(vrs_path),
                            f"{get_pretty_size((await aiofiles.os.stat(vrs_path)).st_size)}",
                            *[
                                _apply_style(feature, feature_status[feature])
                                for feature in features
                            ],
                        )
                    elapsed_time = datetime.now() - self._start_time
                    layout["time_elapsed"].update(
                        Panel(
                            "",
                            title=f":clock1: Time elapsed: [bold][cyan]{_get_pretty_time(elapsed_time)}",
                            title_align="left",
                            box=box.MINIMAL,
                        )
                    ),
                    layout["status_table"].update(copy.deepcopy(table))
                    live.refresh()
                    await asyncio.sleep(1.0)
        except Exception as e:
            logger.error(f"Exception {e}")
            print(e)
            raise e from e


def _get_pretty_time(elapsed_time: timedelta) -> str:
    """
    Convert time delta to human readable format
    """
    seconds = int(elapsed_time.total_seconds())
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days > 0:
        return f"{days}d:{hours}h:{minutes}m:{seconds}s"
    return f"{hours}h:{minutes}m:{seconds}s"


def _apply_style(feature: MpsFeature, state: ModelState) -> Any:
    """
    Apply styling to the given state
    """
    if state.status == ERROR:
        return f":cross_mark: [red]{state.status}({state.error_code})"
    elif state.status == SUCCESS:
        return f":white_check_mark: [green]{state.status}"
    elif state.status == SCHEDULED:
        return f":clock1: {state.status}"
    elif state.status in [UPLOADING, DOWNLOADING]:
        return Spinner("point", f"{state.status} {state.progress:.2f}%")
    elif state.status == ENCRYPTING:
        return f":lock: {state.status} {state.progress:.2f}%"
    elif state.status == HASHING:
        return f":key: {state.status} {state.progress:.2f}%"
    return Spinner("dots", state.status)


def _get_all_features(
    feature_statuses: Mapping[Path, Dict[MpsFeature, ModelState]]
) -> Set[MpsFeature]:
    """
    Return all features that are currently being tracked
    """
    features: Set[MpsFeature] = set()
    for _, feature_state in feature_statuses.items():
        features.update(feature_state.keys())
    return features
