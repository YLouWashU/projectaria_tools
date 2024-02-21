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

from enum import Enum

from textual.app import ComposeResult
from textual.containers import Grid, Horizontal

from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static, Switch


class QuitMode(int, Enum):
    """
    Enum class representing different modes of quitting the app
    """

    QUIT = 1
    LOGOUT_AND_QUIT = 2
    CANCEL = 3


class QuitScreen(ModalScreen[QuitMode]):
    """Screen with a dialog to quit."""

    CSS = """
        QuitScreen {
            align: center middle;
            background: $background 80%;
        }

        #dialog {
            grid-size: 2 3;
            grid-gutter: 1 2;
            grid-rows: 1fr 3fr 3;
            padding: 0 1;
            width: 60;
            height: 11;
            border: thick $background 80%;
            background: $surface;
        }

        #question {
            column-span: 2;
            height: 1fr;
            width: 1fr;
            content-align: center middle;
        }

        #logout_container {
            column-span: 2;
            align: center middle;
        }
        #logout_label{
            height: 3;
            content-align: center middle;
            width: auto;
        }
        #logout {
            background: $surface;
        }

        Button {
            width: 100%;
        }

    """
    BINDINGS = [("escape", "app.pop_screen", "Pop screen")]

    def compose(self) -> ComposeResult:
        """
        Create child widgets for the screen.
        """
        yield Grid(
            Label("[b]Are you sure you want to quit?", id="question"),
            Horizontal(
                Static("Logout", id="logout_label"), Switch(), id="logout_container"
            ),
            Button("Quit", variant="primary", id="quit"),
            Button("Cancel", variant="primary", id="cancel"),
            id="dialog",
        )

    def on_mount(self) -> None:
        """
        Called when the widget is mounted
        """
        self.query_one("#cancel").focus()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """
        Handle button press events.
        """
        logout: bool = self.query_one(Switch).value

        quit_mode: QuitMode = QuitMode.CANCEL
        if event.button.id == "quit":
            quit_mode = QuitMode.LOGOUT_AND_QUIT if logout else QuitMode.QUIT
        self.dismiss(quit_mode)
