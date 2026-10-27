#!/usr/bin/env python3
from __future__ import annotations

import csv
import ctypes
import ctypes.wintypes as wintypes
import os
import queue
import sys
import tempfile
import threading
import time
import unittest
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except Exception:  # A missing Tcl/Tk installation should produce a clear error.
    tk = None  # type: ignore[assignment]
    filedialog = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]


APP_TITLE = "Multi-APP Keyboard Event Logger"
TARGET_EXECUTABLES = (
    "msedge.exe",
    "chrome.exe",
    "notepad.exe",
)
CSV_COLUMNS = (
    "session_id",
    "event_index",
    "timestamp_utc",
    "elapsed_ms",
    "event_type",
    "key_name",
    "virtual_key_code",
    "record_type",
    "marker_label",
    "notes",
)
_STOP = object()


# Common Windows virtual-key identifiers. Unlisted keys use VK_0xNN notation.
_VK_NAMES = {
    0x03: "CANCEL",
    0x08: "BACKSPACE",
    0x09: "TAB",
    0x0C: "CLEAR",
    0x0D: "ENTER",
    0x10: "SHIFT",
    0x11: "CTRL",
    0x12: "ALT",
    0x13: "PAUSE",
    0x14: "CAPS_LOCK",
    0x1B: "ESC",
    0x20: "SPACE",
    0x21: "PAGE_UP",
    0x22: "PAGE_DOWN",
    0x23: "END",
    0x24: "HOME",
    0x25: "LEFT",
    0x26: "UP",
    0x27: "RIGHT",
    0x28: "DOWN",
    0x2C: "PRINT_SCREEN",
    0x2D: "INSERT",
    0x2E: "DELETE",
    0x5B: "LWIN",
    0x5C: "RWIN",
    0x5D: "APPS",
    0x5F: "SLEEP",
    0x6A: "NUMPAD_MULTIPLY",
    0x6B: "NUMPAD_ADD",
    0x6D: "NUMPAD_SUBTRACT",
    0x6E: "NUMPAD_DECIMAL",
    0x6F: "NUMPAD_DIVIDE",
    0x90: "NUM_LOCK",
    0x91: "SCROLL_LOCK",
    0xA0: "LSHIFT",
    0xA1: "RSHIFT",
    0xA2: "LCTRL",
    0xA3: "RCTRL",
    0xA4: "LALT",
    0xA5: "RALT",
    0xBA: "OEM_SEMICOLON",
    0xBB: "OEM_PLUS",
    0xBC: "OEM_COMMA",
    0xBD: "OEM_MINUS",
    0xBE: "OEM_PERIOD",
    0xBF: "OEM_SLASH",
    0xC0: "OEM_BACKTICK",
    0xDB: "OEM_LBRACKET",
    0xDC: "OEM_BACKSLASH",
    0xDD: "OEM_RBRACKET",
    0xDE: "OEM_APOSTROPHE",
    0xE2: "OEM_102",
}


def key_name_from_vk(vk_code: int) -> str:
    """Return a stable, layout-independent label for a Windows virtual key."""
    if 0x30 <= vk_code <= 0x39:  # Top-row digits
        return chr(vk_code)
    if 0x41 <= vk_code <= 0x5A:
        return chr(vk_code)
    if 0x60 <= vk_code <= 0x69:
        return f"NUMPAD{vk_code - 0x60}"
    if 0x70 <= vk_code <= 0x87:
        return f"F{vk_code - 0x6F}"
    if vk_code in _VK_NAMES:
        return _VK_NAMES[vk_code]
    return f"VK_0x{vk_code:02X}"


def utc_iso_timestamp(value: Optional[datetime] = None) -> str:
    """ISO 8601 UTC timestamp with six fractional digits and a Z suffix."""
    moment = value or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def elapsed_milliseconds(start_ns: int, event_ns: int) -> str:
    """Format monotonic elapsed time as milliseconds with microsecond display precision."""
    return f"{max(0, event_ns - start_ns) / 1_000_000:.3f}"


@dataclass(frozen=True)
class CapturedRecord:
    row: tuple[str, ...]


class RecordingSession:
    """Thread-safe session state and asynchronous CSV writer."""

    def __init__(self, output_directory: Path):
        output_directory = output_directory.expanduser()
        output_directory.mkdir(parents=True, exist_ok=True)
        if not output_directory.is_dir():
            raise OSError(f"Output path is not a directory: {output_directory}")

        started_utc = datetime.now(timezone.utc)
        short_id = uuid.uuid4().hex[:8]
        self.session_id = f"session_{started_utc.strftime('%Y%m%d_%H%M%S')}_{short_id}"
        filename = f"keylogger_{started_utc.strftime('%Y%m%d_%H%M%S')}_{short_id}.csv"
        self.path = output_directory / filename

        # Exclusive creation ensures this session never overwrites an older CSV.
        self._file = self.path.open("x", encoding="utf-8", newline="")
        self._csv = csv.writer(self._file, lineterminator="\n")
        self._csv.writerow(CSV_COLUMNS)
        self._file.flush()

        self.started_utc = started_utc
        self.start_monotonic_ns = time.monotonic_ns()
        self._end_monotonic_ns: Optional[int] = None
        self._queue: queue.Queue[object] = queue.Queue()
        self._lock = threading.Lock()
        self._event_index = 0
        self._stopping = False
        self._writer_error: Optional[str] = None
        self._writer_done = threading.Event()
        self._writer_thread = threading.Thread(
            target=self._writer_loop,
            name=f"CSVWriter-{self.session_id}",
            daemon=True,
        )
        self._writer_thread.start()
        self._queue.put(
            CapturedRecord(
                self._make_row(
                    record_type="session_start",
                    mono_ns=self.start_monotonic_ns,
                    utc_timestamp=utc_iso_timestamp(self.started_utc),
                    notes=f"Foreground process filter: {', '.join(TARGET_EXECUTABLES)}; hook: WH_KEYBOARD_LL",
                )
            )
        )

    def _make_row(
        self,
        *,
        record_type: str,
        mono_ns: int,
        utc_timestamp: str,
        event_index: str = "",
        event_type: str = "",
        key_name: str = "",
        virtual_key_code: str = "",
        marker_label: str = "",
        notes: str = "",
    ) -> tuple[str, ...]:
        return (
            self.session_id,
            event_index,
            utc_timestamp,
            elapsed_milliseconds(self.start_monotonic_ns, mono_ns),
            event_type,
            key_name,
            virtual_key_code,
            record_type,
            marker_label,
            notes,
        )

    def record_keyboard_event(self, event_type: str, vk_code: int) -> bool:
        """Queue one event; the caller must first verify app is foreground."""
        if event_type not in ("key_down", "key_up"):
            return False
        with self._lock:
            if self._stopping or self._writer_done.is_set() or self._writer_error:
                return False
            # Stamp while holding the same lock used to order rows, so a stop or
            # marker cannot be written ahead of an event with a later timestamp.
            event_utc = datetime.now(timezone.utc)
            event_mono = time.monotonic_ns()
            self._event_index += 1
            row = self._make_row(
                record_type="keyboard_event",
                mono_ns=event_mono,
                utc_timestamp=utc_iso_timestamp(event_utc),
                event_index=str(self._event_index),
                event_type=event_type,
                key_name=key_name_from_vk(vk_code),
                virtual_key_code=str(vk_code),
            )
            self._queue.put(CapturedRecord(row))
        return True

    def add_sync_marker(self, label: str = "manual_sync_marker") -> bool:
        marker_label = (label.strip() or "manual_sync_marker")[:120]
        with self._lock:
            if self._stopping or self._writer_done.is_set() or self._writer_error:
                return False
            marker_utc = datetime.now(timezone.utc)
            marker_mono = time.monotonic_ns()
            row = self._make_row(
                record_type="sync_marker",
                mono_ns=marker_mono,
                utc_timestamp=utc_iso_timestamp(marker_utc),
                marker_label=marker_label,
                notes="Timestamp is when the marker button was activated.",
            )
            self._queue.put(CapturedRecord(row))
        return True

    @property
    def event_count(self) -> int:
        with self._lock:
            return self._event_index

    @property
    def writer_error(self) -> Optional[str]:
        return self._writer_error

    @property
    def writer_done(self) -> bool:
        return self._writer_done.is_set()

    @property
    def elapsed_ms(self) -> float:
        with self._lock:
            stop_ns = self._end_monotonic_ns
        current_ns = stop_ns if stop_ns is not None else time.monotonic_ns()
        return max(0, current_ns - self.start_monotonic_ns) / 1_000_000

    def _writer_loop(self) -> None:
        last_flush = time.monotonic()
        rows_since_flush = 0
        try:
            while True:
                try:
                    item = self._queue.get(timeout=0.5)
                except queue.Empty:
                    self._file.flush()
                    last_flush = time.monotonic()
                    rows_since_flush = 0
                    continue

                if item is _STOP:
                    self._file.flush()
                    break
                if not isinstance(item, CapturedRecord):
                    continue

                self._csv.writerow(item.row)
                rows_since_flush += 1
                if rows_since_flush >= 25 or time.monotonic() - last_flush >= 0.5:
                    self._file.flush()
                    last_flush = time.monotonic()
                    rows_since_flush = 0
        except Exception as exc:
            self._writer_error = f"CSV writer failed: {type(exc).__name__}: {exc}"
        finally:
            try:
                self._file.flush()
            except Exception as exc:
                if not self._writer_error:
                    self._writer_error = f"CSV flush failed: {type(exc).__name__}: {exc}"
            try:
                self._file.close()
            except Exception as exc:
                if not self._writer_error:
                    self._writer_error = f"CSV close failed: {type(exc).__name__}: {exc}"
            self._writer_done.set()

    def stop(self, reason: str = "User stopped recording") -> None:
        with self._lock:
            if self._stopping:
                pass
            else:
                self._stopping = True
                stop_utc = datetime.now(timezone.utc)
                stop_mono = time.monotonic_ns()
                self._end_monotonic_ns = stop_mono
                # If the writer has failed, it cannot reliably accept an end row.
                if not self._writer_done.is_set():
                    row = self._make_row(
                        record_type="session_end",
                        mono_ns=stop_mono,
                        utc_timestamp=utc_iso_timestamp(stop_utc),
                        notes=reason,
                    )
                    self._queue.put(CapturedRecord(row))
                    self._queue.put(_STOP)
        self._writer_thread.join()


# ---------------- Windows foreground identification and keyboard hook --------


class Win32API:
    """Thin ctypes wrappers around the Windows APIs used by the application."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Keyboard capture is available only on Windows.")
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        self.user32.GetForegroundWindow.argtypes = []
        self.user32.GetForegroundWindow.restype = ctypes.c_void_p
        self.user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        self.user32.GetWindowThreadProcessId.restype = ctypes.c_uint32

        self.kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.kernel32.OpenProcess.restype = ctypes.c_void_p
        self.kernel32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_wchar),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self.kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
        self.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel32.CloseHandle.restype = ctypes.c_int

        self.kernel32.GetCurrentThreadId.argtypes = []
        self.kernel32.GetCurrentThreadId.restype = ctypes.c_uint32
        self.kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        self.kernel32.GetModuleHandleW.restype = ctypes.c_void_p

        self.user32.PeekMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG), ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32
        ]
        self.user32.PeekMessageW.restype = ctypes.c_int
        self.user32.GetMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG), ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32
        ]
        self.user32.GetMessageW.restype = ctypes.c_int
        self.user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        self.user32.TranslateMessage.restype = ctypes.c_int
        self.user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        self.user32.DispatchMessageW.restype = ctypes.c_ssize_t
        self.user32.PostThreadMessageW.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_size_t, ctypes.c_ssize_t
        ]
        self.user32.PostThreadMessageW.restype = ctypes.c_int
        self.user32.UnhookWindowsHookEx.argtypes = [ctypes.c_void_p]
        self.user32.UnhookWindowsHookEx.restype = ctypes.c_int
        self.user32.CallNextHookEx.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t, ctypes.c_ssize_t
        ]
        self.user32.CallNextHookEx.restype = ctypes.c_ssize_t

    def foreground_process_id(self) -> Optional[int]:
        hwnd = self.user32.GetForegroundWindow()
        if not hwnd:
            return None
        pid = ctypes.c_uint32(0)
        self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return int(pid.value) if pid.value else None

    def process_executable_name(self, pid_value: Optional[int]) -> Optional[str]:
        if pid_value is None or pid_value <= 0:
            return None
        # PROCESS_QUERY_LIMITED_INFORMATION works for ordinary same-user process
        # identification and generally avoids requiring administrator privileges.
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        process_handle = self.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid_value)
        if not process_handle:
            return None
        try:
            capacity = 32768
            buffer = ctypes.create_unicode_buffer(capacity)
            size = ctypes.c_uint32(capacity)
            ok = self.kernel32.QueryFullProcessImageNameW(
                process_handle, 0, buffer, ctypes.byref(size)
            )
            if not ok or size.value == 0:
                return None
            return os.path.basename(buffer.value[: size.value]).casefold()
        finally:
            self.kernel32.CloseHandle(process_handle)

    def foreground_executable_name(self) -> Optional[str]:
        pid_value = self.foreground_process_id()
        return self.process_executable_name(pid_value) if pid_value else None


_API: Optional[Win32API] = None
_API_LOCK = threading.Lock()


def get_win_api() -> Win32API:
    global _API
    if _API is None:
        with _API_LOCK:
            if _API is None:
                _API = Win32API()
    return _API


def is_target_app_foreground() -> bool:
    """Return True when a configured application is foreground."""
    try:
        executable = get_win_api().foreground_executable_name()
        return executable in {
            name.casefold() for name in TARGET_EXECUTABLES
        }
    except Exception:
        return False


class KBDLLHOOKSTRUCT(ctypes.Structure):
    # ULONG_PTR is pointer-sized; c_size_t is correct for 32- and 64-bit Windows.
    _fields_ = [
        ("vkCode", ctypes.c_uint32),
        ("scanCode", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("time", ctypes.c_uint32),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class Win32KeyboardHook:
    """Run WH_KEYBOARD_LL on its own thread with a Windows message loop."""

    WH_KEYBOARD_LL = 13
    HC_ACTION = 0
    WM_KEYDOWN = 0x0100
    WM_KEYUP = 0x0101
    WM_SYSKEYDOWN = 0x0104
    WM_SYSKEYUP = 0x0105
    WM_QUIT = 0x0012
    PM_NOREMOVE = 0x0000
    LLKHF_INJECTED = 0x10

    def __init__(self, session: RecordingSession):
        self.session = session
        self._thread = threading.Thread(target=self._run, name="KeyboardHookThread", daemon=True)
        self._ready = threading.Event()
        self._thread_id: Optional[int] = None
        self._hook_handle: Optional[int] = None
        self._hook_proc = None
        self.error: Optional[str] = None
        self.callback_error: Optional[str] = None
        self._api: Optional[Win32API] = None
        self._monitor_stop = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._target_pid: Optional[int] = None

    def start(self, timeout: float = 5.0) -> None:
        self._thread.start()
        if not self._ready.wait(timeout):
            self.stop()
            raise RuntimeError("Timed out while initializing the Windows keyboard hook.")
        if self.error:
            self.stop()
            raise RuntimeError(self.error)

    def _run(self) -> None:
        try:
            self._api = get_win_api()
            api = self._api
            self._thread_id = int(api.kernel32.GetCurrentThreadId())

            HOOKPROC = ctypes.WINFUNCTYPE(
                ctypes.c_ssize_t, ctypes.c_int, ctypes.c_size_t, ctypes.c_ssize_t
            )
            self._hook_proc = HOOKPROC(self._on_keyboard_message)

            # Creating the message queue before signalling ready makes PostThreadMessage
            # reliable when Stop is pressed soon after startup.
            msg = wintypes.MSG()
            api.user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, self.PM_NOREMOVE)
            module_handle = api.kernel32.GetModuleHandleW(None)
            api.user32.SetWindowsHookExW.argtypes = [
                ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32
            ]
            api.user32.SetWindowsHookExW.restype = ctypes.c_void_p
            handle = api.user32.SetWindowsHookExW(
                self.WH_KEYBOARD_LL,
                ctypes.cast(self._hook_proc, ctypes.c_void_p),
                module_handle,
                0,
            )
            if not handle:
                error_code = ctypes.get_last_error()
                self.error = (
                    "SetWindowsHookExW failed. Windows error "
                    f"{error_code}: {ctypes.FormatError(error_code).strip()}"
                )
                self._ready.set()
                return

            self._hook_handle = handle
            # Process-name lookup runs off the low-level hook callback. The callback
            # only compares the current foreground PID with this cached target PID.
            self._monitor_thread = threading.Thread(
                target=self._monitor_foreground_process,
                name="ForegroundProcessMonitor",
                daemon=True,
            )
            self._monitor_thread.start()
            self._ready.set()
            while True:
                result = api.user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if result == 0:  # WM_QUIT
                    break
                if result == -1:
                    error_code = ctypes.get_last_error()
                    self.error = (
                        "The keyboard-hook message loop failed. Windows error "
                        f"{error_code}: {ctypes.FormatError(error_code).strip()}"
                    )
                    break
                api.user32.TranslateMessage(ctypes.byref(msg))
                api.user32.DispatchMessageW(ctypes.byref(msg))
        except Exception as exc:
            self.error = f"Keyboard-hook initialization/runtime failure: {type(exc).__name__}: {exc}"
            self._ready.set()
        finally:
            self._monitor_stop.set()
            if self._hook_handle and self._api is not None:
                if not self._api.user32.UnhookWindowsHookEx(self._hook_handle) and not self.error:
                    error_code = ctypes.get_last_error()
                    self.error = f"UnhookWindowsHookEx failed (Windows error {error_code})."
                self._hook_handle = None
            if self._monitor_thread is not None and self._monitor_thread.is_alive():
                self._monitor_thread.join(timeout=1.0)
            self._ready.set()

    def _monitor_foreground_process(self) -> None:
        api = self._api
        if api is None:
            return

        targets = {name.casefold() for name in TARGET_EXECUTABLES}

        while not self._monitor_stop.is_set():
            try:
                pid = api.foreground_process_id()
                executable = api.process_executable_name(pid) if pid else None

                self._target_pid = (
                    pid if executable in targets else None
                )
            except Exception:
                self._target_pid = None

            self._monitor_stop.wait(0.05)

    def _on_keyboard_message(self, n_code: int, w_param: int, l_param: int) -> int:
        api = self._api
        if api is None or self._hook_handle is None:
            return 0
        try:
            if n_code == self.HC_ACTION:
                message = int(w_param)
                if message in (self.WM_KEYDOWN, self.WM_SYSKEYDOWN, self.WM_KEYUP, self.WM_SYSKEYUP):
                    key_data = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                    # Ignore events explicitly marked by Windows as injected/synthetic.
                    # This is an input-quality filter, not an anti-cheat bypass.
                    if not (key_data.flags & self.LLKHF_INJECTED):
                        foreground_pid = api.foreground_process_id()
                        if foreground_pid and foreground_pid == self._target_pid:
                            event_type = (
                                "key_down" if message in (self.WM_KEYDOWN, self.WM_SYSKEYDOWN) else "key_up"
                            )
                            self.session.record_keyboard_event(event_type, int(key_data.vkCode))
        except Exception as exc:
            if self.callback_error is None:
                self.callback_error = f"Keyboard callback error: {type(exc).__name__}: {exc}"
        return int(api.user32.CallNextHookEx(self._hook_handle, n_code, w_param, l_param))

    def stop(self) -> None:
        self._monitor_stop.set()
        api = self._api
        thread_id = self._thread_id
        if api is not None and thread_id and self._thread.is_alive():
            posted = api.user32.PostThreadMessageW(thread_id, self.WM_QUIT, 0, 0)
            if not posted and not self.error:
                error_code = ctypes.get_last_error()
                self.error = f"Could not stop keyboard-hook message loop (Windows error {error_code})."
        if self._thread.is_alive():
            self._thread.join(timeout=5.0)
        if self._thread.is_alive() and not self.error:
            self.error = "Keyboard-hook thread did not stop within five seconds."
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=1.0)


# ------------------------------ Tkinter GUI ----------------------------------


class KeyboardLoggerApp:
    def __init__(self, root) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("690x465")
        self.root.minsize(620, 430)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        default_output = Path.home() / "Documents" / "KeyLogs"
        self.output_directory_var = tk.StringVar(value=str(default_output))
        self.status_var = tk.StringVar(value="Stopped")
        self.timer_var = tk.StringVar(value="00:00:00.000")
        self.event_count_var = tk.StringVar(value="0")
        self.file_var = tk.StringVar(value="No session created yet")
        self.marker_label_var = tk.StringVar(value="manual_sync_marker")
        self.detail_var = tk.StringVar(value="Ready. Start recording before switching to app.")

        self.active_session: Optional[RecordingSession] = None
        self.last_session: Optional[RecordingSession] = None
        self.hook: Optional[Win32KeyboardHook] = None
        self._closing = False
        self._reported_capture_error: Optional[str] = None

        self._build_ui()
        if os.name != "nt":
            self.status_var.set("Unavailable — Windows only")
            self.detail_var.set("Keyboard capture requires Windows APIs; CSV self-tests work on this system.")
            self.start_button.configure(state="disabled")
        self.root.after(200, self._poll_ui)

    def _build_ui(self) -> None:
        outer = tk.Frame(self.root, padx=18, pady=16)
        outer.pack(fill="both", expand=True)

        tk.Label(outer, text="Keyboard Event Logger", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(
            outer,
            text="Logs key-down/key-up events only while app's process is foreground.",
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(3, 14))

        status_frame = tk.LabelFrame(outer, text="Session", padx=12, pady=9)
        status_frame.pack(fill="x", pady=(0, 10))
        row = tk.Frame(status_frame)
        row.pack(fill="x")
        tk.Label(row, text="Status:", font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(row, textvariable=self.status_var, anchor="w").pack(side="left", padx=(8, 24))
        tk.Label(row, text="Elapsed:", font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(row, textvariable=self.timer_var, font=("Consolas", 11)).pack(side="left", padx=(8, 24))
        tk.Label(row, text="Events:", font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(row, textvariable=self.event_count_var, font=("Consolas", 11)).pack(side="left", padx=(8, 0))

        output_frame = tk.LabelFrame(outer, text="CSV output", padx=12, pady=9)
        output_frame.pack(fill="x", pady=(0, 10))
        tk.Label(output_frame, text="Save directory:").grid(row=0, column=0, sticky="w")
        self.output_entry = tk.Entry(output_frame, textvariable=self.output_directory_var)
        self.output_entry.grid(row=1, column=0, sticky="ew", pady=(3, 7))
        self.browse_button = tk.Button(output_frame, text="Browse…", command=self._browse_directory)
        self.browse_button.grid(row=1, column=1, sticky="e", padx=(8, 0), pady=(3, 7))
        tk.Label(output_frame, text="Current/last CSV:").grid(row=2, column=0, sticky="w")
        tk.Label(output_frame, textvariable=self.file_var, anchor="w", justify="left", wraplength=560).grid(
            row=3, column=0, columnspan=2, sticky="ew", pady=(3, 0)
        )
        output_frame.columnconfigure(0, weight=1)

        marker_frame = tk.Frame(outer)
        marker_frame.pack(fill="x", pady=(0, 10))
        tk.Label(marker_frame, text="Marker label:").pack(side="left")
        self.marker_entry = tk.Entry(marker_frame, textvariable=self.marker_label_var, width=25)
        self.marker_entry.pack(side="left", padx=(7, 8))
        self.marker_button = tk.Button(marker_frame, text="Insert Sync Marker", command=self._add_marker, state="disabled")
        self.marker_button.pack(side="left")

        buttons = tk.Frame(outer)
        buttons.pack(fill="x", pady=(3, 10))
        self.start_button = tk.Button(
            buttons, text="Start Recording", command=self._start_recording, width=18, height=2
        )
        self.start_button.pack(side="left")
        self.stop_button = tk.Button(
            buttons, text="Stop Recording", command=self._stop_recording, width=18, height=2, state="disabled"
        )
        self.stop_button.pack(side="left", padx=(10, 0))

        tk.Label(outer, textvariable=self.detail_var, fg="#444444", wraplength=640, justify="left").pack(
            anchor="w", pady=(3, 0)
        )
        tk.Label(
            outer,
            fg="#7a3b00",
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(8, 0))

    def _browse_directory(self) -> None:
        selected = filedialog.askdirectory(
            title="Choose CSV output directory",
            initialdir=self.output_directory_var.get() or str(Path.home()),
            mustexist=False,
        )
        if selected:
            self.output_directory_var.set(selected)

    def _start_recording(self) -> None:
        if self.active_session is not None:
            return
        if os.name != "nt":
            self._show_error("Windows is required for keyboard capture. The CSV self-test is platform independent.")
            return

        session: Optional[RecordingSession] = None
        hook: Optional[Win32KeyboardHook] = None
        try:
            output_text = self.output_directory_var.get().strip()
            if not output_text:
                raise OSError("Choose an output directory first.")
            output_directory = Path(output_text).expanduser()
            output_directory.mkdir(parents=True, exist_ok=True)
            session = RecordingSession(output_directory)
            hook = Win32KeyboardHook(session)
            hook.start()
        except Exception as exc:
            if hook is not None:
                hook.stop()
            if session is not None:
                session.stop("Capture initialization failed")
            self.last_session = session
            if session is not None:
                self.file_var.set(str(session.path))
            self.status_var.set("Error")
            self.detail_var.set(f"Could not start capture: {type(exc).__name__}: {exc}")
            self._show_error(self.detail_var.get())
            return

        self.active_session = session
        self.last_session = session
        self.hook = hook
        self._reported_capture_error = None
        self.file_var.set(str(session.path))
        self.status_var.set("Recording — waiting for app foreground")
        self.detail_var.set("Switch to app to begin logging. Events from other foreground applications are not saved.")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.marker_button.configure(state="normal")
        self.browse_button.configure(state="disabled")
        self.output_entry.configure(state="disabled")

    def _stop_recording(self) -> None:
        self._finish_session("User stopped recording", show_capture_error=True)

    def _finish_session(self, reason: str, show_capture_error: bool) -> None:
        session = self.active_session
        hook = self.hook
        if session is None:
            return

        self.status_var.set("Stopping and flushing CSV…")
        self.root.update_idletasks()
        hook_error = None
        if hook is not None:
            hook.stop()
            hook_error = hook.error or hook.callback_error
        session.stop(reason)
        writer_error = session.writer_error

        self.active_session = None
        self.hook = None
        self.last_session = session
        self.status_var.set("Stopped with error" if (hook_error or writer_error) else "Stopped")
        self.detail_var.set(
            f"Session saved to {session.path} ({session.event_count} keyboard events)."
            if not (hook_error or writer_error)
            else f"Session stopped. {writer_error or hook_error}"
        )
        self.start_button.configure(state="normal" if os.name == "nt" else "disabled")
        self.stop_button.configure(state="disabled")
        self.marker_button.configure(state="disabled")
        self.browse_button.configure(state="normal")
        self.output_entry.configure(state="normal")

        if show_capture_error and (hook_error or writer_error):
            self._show_error(writer_error or hook_error or "Unknown capture error")

    def _add_marker(self) -> None:
        session = self.active_session
        if session is None:
            return
        if session.add_sync_marker(self.marker_label_var.get()):
            self.detail_var.set("Sync marker queued. It records the UTC and elapsed time of this button action.")
        elif session.writer_error:
            self._finish_session("Stopped after CSV writer error", show_capture_error=True)

    def _poll_ui(self) -> None:
        if self._closing:
            return
        session = self.active_session
        if session is not None:
            self.timer_var.set(self._format_timer(session.elapsed_ms))
            self.event_count_var.set(str(session.event_count))
            hook = self.hook
            error = session.writer_error
            if hook is not None:
                error = error or hook.error or hook.callback_error

            if error:
                self._finish_session("Capture stopped after an error", show_capture_error=True)
            elif is_target_app_foreground():
                self.status_var.set("Recording — target app foreground")
            else:
                self.status_var.set("Recording — waiting for target app")
        elif self.last_session is not None:
            self.timer_var.set(self._format_timer(self.last_session.elapsed_ms))
            self.event_count_var.set(str(self.last_session.event_count))
        self.root.after(200, self._poll_ui)

    @staticmethod
    def _format_timer(milliseconds: float) -> str:
        total_ms = max(0, int(milliseconds))
        hours, remainder = divmod(total_ms, 3_600_000)
        minutes, remainder = divmod(remainder, 60_000)
        seconds, millis = divmod(remainder, 1_000)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}.{millis:03d}"

    def _show_error(self, message: str) -> None:
        if messagebox is not None:
            messagebox.showerror("Keyboard Logger", message, parent=self.root)

    def _on_close(self) -> None:
        self._closing = True
        if self.active_session is not None:
            self._finish_session("Application closed", show_capture_error=False)
        self.root.destroy()


def run_self_tests() -> bool:
    """Small cross-platform integration tests for timestamps and CSV writing."""

    class LoggerTests(unittest.TestCase):
        def test_key_names(self):
            self.assertEqual(key_name_from_vk(0x57), "W")
            self.assertEqual(key_name_from_vk(0x20), "SPACE")
            self.assertEqual(key_name_from_vk(0x70), "F1")
            self.assertEqual(key_name_from_vk(0x123), "VK_0x123")

        def test_utc_and_elapsed_format(self):
            test_time = datetime(2026, 10, 27, 10, 0, 0, 125000, tzinfo=timezone.utc)
            self.assertEqual(utc_iso_timestamp(test_time), "2026-10-27T10:00:00.125000Z")
            self.assertEqual(elapsed_milliseconds(1_000_000_000, 1_125_000_000), "125.000")
            self.assertEqual(elapsed_milliseconds(100, 50), "0.000")

        def test_csv_events_marker_and_session_metadata(self):
            with tempfile.TemporaryDirectory() as temp_dir:
                session = RecordingSession(Path(temp_dir))
                session.record_keyboard_event("key_down", 0x57)
                session.record_keyboard_event("key_up", 0x57)
                session.add_sync_marker("test_marker")
                session.stop("Self-test complete")

                with session.path.open("r", encoding="utf-8", newline="") as source:
                    records = list(csv.DictReader(source))

                self.assertEqual(len(records), 5)  # start + 2 keys + marker + end
                self.assertEqual(records[0]["record_type"], "session_start")
                self.assertEqual(records[-1]["record_type"], "session_end")
                keyboard = [row for row in records if row["record_type"] == "keyboard_event"]
                self.assertEqual([row["event_index"] for row in keyboard], ["1", "2"])
                self.assertEqual([row["event_type"] for row in keyboard], ["key_down", "key_up"])
                self.assertEqual([row["key_name"] for row in keyboard], ["W", "W"])
                self.assertTrue(all(row["timestamp_utc"].endswith("Z") for row in records))
                self.assertTrue(all(row["elapsed_ms"] != "" for row in records))
                elapsed = [float(row["elapsed_ms"]) for row in records]
                self.assertEqual(elapsed, sorted(elapsed))
                self.assertTrue(any(row["marker_label"] == "test_marker" for row in records))
                self.assertEqual(records[1]["virtual_key_code"], "87")

        def test_each_session_gets_a_distinct_file(self):
            with tempfile.TemporaryDirectory() as temp_dir:
                first = RecordingSession(Path(temp_dir))
                first.stop("test")
                second = RecordingSession(Path(temp_dir))
                second.stop("test")
                self.assertNotEqual(first.path, second.path)
                self.assertTrue(first.path.exists())
                self.assertTrue(second.path.exists())

        def test_output_path_that_is_a_file_fails_clearly(self):
            with tempfile.TemporaryDirectory() as temp_dir:
                not_a_directory = Path(temp_dir) / "already-a-file"
                not_a_directory.write_text("x", encoding="utf-8")
                with self.assertRaises(OSError):
                    RecordingSession(not_a_directory)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LoggerTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return result.wasSuccessful()


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--self-test" in args:
        return 0 if run_self_tests() else 1

    if tk is None:
        print(
            "Tkinter is not available in this Python installation. Install Python with Tcl/Tk support.",
            file=sys.stderr,
        )
        return 2

    try:
        root = tk.Tk()
    except Exception as exc:
        print(f"Could not open the Tkinter GUI: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    KeyboardLoggerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
