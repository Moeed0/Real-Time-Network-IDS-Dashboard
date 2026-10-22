from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


FINGERPRINT_BYTES = 256


@dataclass
class TailState:
    path: str
    inode: int
    offset: int
    fingerprint: str | None = None
    fingerprint_length: int = 0


class PersistentJsonTailer:
    """
    Persistent newline-delimited JSON tailer.

    State contains:
      - path
      - inode
      - acknowledged byte offset
      - fingerprint of the beginning of the file

    The fingerprint protects against copytruncate rotation where the file
    keeps the same inode and has already grown beyond the old offset before
    the next poll.

    The read cursor is kept in memory so normal polling does not reread data.
    Persisted state advances only after the caller acknowledges successful
    processing.
    """

    def __init__(
        self,
        path: Path,
        state_file: Path,
        source_key: str,
        *,
        start_at_end: bool = True,
        encoding: str = "utf-8",
    ) -> None:
        self.path = path.resolve()
        self.state_file = state_file.resolve()
        self.source_key = source_key
        self.start_at_end = start_at_end
        self.encoding = encoding

        self.state_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.state = self._load_state()

        self._read_inode: int | None = None
        self._read_offset: int | None = None
        self._read_fingerprint: str | None = None
        self._read_fingerprint_length: int = 0

    def _load_state(self) -> dict[str, dict]:
        if not self.state_file.exists():
            return {}

        try:
            data = json.loads(
                self.state_file.read_text(
                    encoding="utf-8",
                )
            )

            if not isinstance(data, dict):
                raise ValueError(
                    "state file root must be an object"
                )

            return data

        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(
                f"Cannot read tail state file "
                f"{self.state_file}: {exc}"
            ) from exc

    def _save_state(self) -> None:
        """
        Merge this tailer's state with the latest state on disk.

        Snort and Suricata share one state file but use separate tailer
        instances, so a write must preserve the other engine's position.
        """
        current = self._load_state()

        for key, value in self.state.items():
            current[key] = value

        self.state = current

        temp = self.state_file.with_suffix(
            self.state_file.suffix + ".tmp"
        )

        payload = json.dumps(
            self.state,
            indent=2,
            sort_keys=True,
        )

        temp.write_text(
            payload + "\n",
            encoding="utf-8",
        )

        temp.replace(self.state_file)

    def _current_file_info(self) -> tuple[int, int]:
        stat = self.path.stat()

        return (
            int(stat.st_ino),
            int(stat.st_size),
        )

    def _fingerprint(
        self,
        length: int,
    ) -> str:
        if length < 0:
            raise ValueError(
                "fingerprint length cannot be negative"
            )

        if length == 0:
            return hashlib.sha256(b"").hexdigest()

        with self.path.open("rb") as f:
            data = f.read(length)

        if len(data) != length:
            raise ValueError(
                f"Cannot fingerprint {length} bytes; "
                f"file only provided {len(data)} bytes"
            )

        return hashlib.sha256(data).hexdigest()

    def _fingerprint_for_size(
        self,
        size: int,
    ) -> tuple[str, int]:
        length = min(
            FINGERPRINT_BYTES,
            max(size, 0),
        )

        return (
            self._fingerprint(length),
            length,
        )

    def _saved_prefix_matches(
        self,
        saved: dict,
        current_size: int,
    ) -> bool:
        fingerprint = saved.get("fingerprint")
        fingerprint_length = saved.get(
            "fingerprint_length"
        )

        if not isinstance(fingerprint, str):
            return True

        if not isinstance(
            fingerprint_length,
            int,
        ):
            return True

        if fingerprint_length < 0:
            return True

        if fingerprint_length == 0:
            return True

        if current_size < fingerprint_length:
            return False

        current = self._fingerprint(
            fingerprint_length
        )

        return current == fingerprint

    def _starting_position(
        self,
        inode: int,
        size: int,
    ) -> tuple[int, str | None, int]:
        saved = self.state.get(
            self.source_key
        )

        if not isinstance(saved, dict):
            if self.start_at_end:
                fingerprint, fingerprint_length = (
                    self._fingerprint_for_size(size)
                )
                return (
                    size,
                    fingerprint,
                    fingerprint_length,
                )

            fingerprint, fingerprint_length = (
                self._fingerprint_for_size(size)
            )

            return (
                0,
                fingerprint,
                fingerprint_length,
            )

        saved_inode = saved.get("inode")
        saved_offset = saved.get("offset")

        if not isinstance(saved_inode, int):
            if self.start_at_end:
                fingerprint, fingerprint_length = (
                    self._fingerprint_for_size(size)
                )
                return (
                    size,
                    fingerprint,
                    fingerprint_length,
                )

            fingerprint, fingerprint_length = (
                self._fingerprint_for_size(size)
            )

            return (
                0,
                fingerprint,
                fingerprint_length,
            )

        if not isinstance(saved_offset, int):
            fingerprint, fingerprint_length = (
                self._fingerprint_for_size(size)
            )
            return (
                size if self.start_at_end else 0,
                fingerprint,
                fingerprint_length,
            )

        # Rename/recreate rotation.
        if saved_inode != inode:
            fingerprint, fingerprint_length = (
                self._fingerprint_for_size(size)
            )
            return (
                0,
                fingerprint,
                fingerprint_length,
            )

        # Classic copytruncate case.
        if size < saved_offset:
            fingerprint, fingerprint_length = (
                self._fingerprint_for_size(size)
            )
            return (
                0,
                fingerprint,
                fingerprint_length,
            )

        # Critical copytruncate case:
        # same inode, but the beginning of the file changed even though the
        # new file is already larger than the old acknowledged offset.
        if not self._saved_prefix_matches(
            saved,
            size,
        ):
            fingerprint, fingerprint_length = (
                self._fingerprint_for_size(size)
            )
            return (
                0,
                fingerprint,
                fingerprint_length,
            )

        fingerprint = saved.get("fingerprint")
        fingerprint_length = saved.get(
            "fingerprint_length"
        )

        if not isinstance(fingerprint, str):
            fingerprint = None

        if not isinstance(
            fingerprint_length,
            int,
        ):
            fingerprint_length = 0

        return (
            saved_offset,
            fingerprint,
            fingerprint_length,
        )

    def _initialize_read_position(self) -> None:
        inode, size = self._current_file_info()

        (
            self._read_offset,
            self._read_fingerprint,
            self._read_fingerprint_length,
        ) = self._starting_position(
            inode,
            size,
        )

        self._read_inode = inode

        # When starting at EOF with no previous state, persist that initial
        # position so a restart does not replay historical content.
        if (
            self.source_key not in self.state
            and self.start_at_end
        ):
            self.state[self.source_key] = {
                "path": str(self.path),
                "inode": inode,
                "offset": self._read_offset,
                "fingerprint": self._read_fingerprint,
                "fingerprint_length": (
                    self._read_fingerprint_length
                ),
            }

            self._save_state()

    def _synchronize_read_position(self) -> None:
        if (
            self._read_inode is None
            or self._read_offset is None
        ):
            self._initialize_read_position()
            return

        inode, size = self._current_file_info()

        # New inode: rename/recreate rotation.
        if inode != self._read_inode:
            (
                self._read_fingerprint,
                self._read_fingerprint_length,
            ) = self._fingerprint_for_size(size)

            self._read_inode = inode
            self._read_offset = 0
            return

        # Same inode became smaller.
        if size < self._read_offset:
            (
                self._read_fingerprint,
                self._read_fingerprint_length,
            ) = self._fingerprint_for_size(size)

            self._read_offset = 0
            return

        # Same inode, but prefix changed.
        # This catches copytruncate even when the new file is already larger
        # than the previous read offset.
        if (
            self._read_fingerprint is not None
            and self._read_fingerprint_length > 0
        ):
            if size < self._read_fingerprint_length:
                (
                    self._read_fingerprint,
                    self._read_fingerprint_length,
                ) = self._fingerprint_for_size(size)

                self._read_offset = 0
                return

            current = self._fingerprint(
                self._read_fingerprint_length
            )

            if current != self._read_fingerprint:
                (
                    self._read_fingerprint,
                    self._read_fingerprint_length,
                ) = self._fingerprint_for_size(size)

                self._read_offset = 0

    def poll(
        self,
        callback: Callable[
            [str, int, int],
            None,
        ],
    ) -> int:
        """
        Read complete newline-delimited records currently available.

        callback(line, inode, end_offset) is called for each complete line.

        The in-memory cursor advances after the callback succeeds.
        Persisted state advances only when acknowledge() is called.

        A final line without a newline is left unread.
        """
        self._synchronize_read_position()

        assert self._read_inode is not None
        assert self._read_offset is not None

        inode = self._read_inode
        offset = self._read_offset
        delivered = 0

        with self.path.open(
            "r",
            encoding=self.encoding,
            errors="replace",
            newline="",
        ) as f:
            f.seek(offset)

            while True:
                line_start = f.tell()
                line = f.readline()

                if not line:
                    break

                if not line.endswith("\n"):
                    # Do not consume a partial JSON line.
                    f.seek(line_start)
                    break

                end_offset = f.tell()

                callback(
                    line.rstrip("\r\n"),
                    inode,
                    end_offset,
                )

                self._read_offset = end_offset
                delivered += 1

        return delivered

    def acknowledge(
        self,
        inode: int,
        end_offset: int,
    ) -> None:
        """
        Persist a successfully processed source position.
        """
        if end_offset < 0:
            raise ValueError(
                "end_offset cannot be negative"
            )

        current_inode, current_size = (
            self._current_file_info()
        )

        if current_inode != inode:
            raise RuntimeError(
                "Cannot acknowledge data from an old inode"
            )

        if end_offset > current_size:
            raise ValueError(
                f"Cannot acknowledge offset {end_offset}; "
                f"file size is {current_size}."
            )

        fingerprint, fingerprint_length = (
            self._fingerprint_for_size(
                current_size
            )
        )

        self.state[self.source_key] = {
            "path": str(self.path),
            "inode": int(inode),
            "offset": int(end_offset),
            "fingerprint": fingerprint,
            "fingerprint_length": (
                fingerprint_length
            ),
        }

        self._save_state()

        self._read_inode = int(inode)
        self._read_offset = int(end_offset)
        self._read_fingerprint = fingerprint
        self._read_fingerprint_length = (
            fingerprint_length
        )

    def reset(self) -> None:
        self.state.pop(
            self.source_key,
            None,
        )

        self._read_inode = None
        self._read_offset = None
        self._read_fingerprint = None
        self._read_fingerprint_length = 0

        self._save_state()
