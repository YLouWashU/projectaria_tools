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

import logging

from rich.text import Text

from textual.app import ComposeResult
from textual.containers import Grid, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static, Switch

from .authentication import AuthenticationError


logger = logging.getLogger(__name__)


class LoginScreen(ModalScreen[bool]):
    """Login screen"""

    CSS = """
    LoginScreen {
        align: center middle;
        background: $background 100%;
    }

    .label {
        color: $foreground;
        content-align: right middle;
    }

    #dialog {
        grid-size: 3 5;
        grid-gutter: 1 2;
        grid-rows: 2 3 3 3 3;
        padding: 1 1;
        width: 60;
        height: 24;
        border: thick $background 80%;
        background: $surface;
    }

    #title {
        column-span: 3;
        content-align: center middle;
    }

    .label {
        column-span: 1;
        content-align: right middle;
        height: 3
    }

    #remember_me_label {
        height: 3;
        content-align: center middle;
        width: auto;
    }

    #username, #password {
        column-span: 2;
        height: 4;
        padding: 0 1;
    }

    Button {
        width: 100%;
        height: 5;
        text-align: center;
    }

    #container, #buttons {
        column-span: 3;
        align: center middle;
        height: 3;
    }

    """

    def compose(self) -> ComposeResult:
        """Create child widgets for the screen."""
        self._login_attempt: int = 1

        yield Grid(
            Static("[b]Login to Aria Machine Perception Services", id="title"),
            Static("Username", classes="label"),
            Input(placeholder="Username", id="username"),
            Static("Password", classes="label"),
            Input(placeholder="Password", id="password", password=True),
            Horizontal(
                Static("Remember me?", id="remember_me_label"),
                Switch(True),
                id="container",
            ),
            Static(id="login_error"),
            Button("Cancel", variant="primary", id="cancel"),
            Button("Login", variant="primary", id="login"),
            id="dialog",
        )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """
        Handle button press events.
        """
        if event.button.id == "cancel":
            self.dismiss(False)
            return
        elif event.button.id == "login":
            username = self.query_one("#username", Input).value.strip()
            password = self.query_one("#password", Input).value.strip()
            logger.debug(f"Logging in as {username} {password}")
            if username and password:
                try:
                    if await self.app._authenticator.login(
                        username, password, self.query_one(Switch).value
                    ):
                        self.dismiss(True)
                        return
                except AuthenticationError as e:
                    logger.exception(e)
            if self._login_attempt < 3:
                self.query_one("#login_error").update(
                    Text.from_markup(f"[red]Login Failed ({self._login_attempt}/3)")
                )
                self._login_attempt += 1
            else:
                self.dismiss(False)
