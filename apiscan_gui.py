#!/usr/bin/env python3
########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.0 07-07-2026                               #
########################################################


from __future__ import annotations
import builtins
import json
import os
import re
import subprocess
import sys
import threading
import time
import queue
from datetime import datetime
from pathlib import Path
from tkinter import (
    Tk, Toplevel, ttk, filedialog, messagebox, StringVar, IntVar, BooleanVar,
    Text, END, Canvas,
    N, S, E, W,
    DISABLED, NORMAL, VERTICAL, HORIZONTAL, HIDDEN,
    Frame, Label, Entry, Button, Checkbutton, OptionMenu,
    PhotoImage
)
from tkinter.scrolledtext import ScrolledText
from typing import Any

try:
    from PIL import Image, ImageTk
except ImportError:
    Image = None
    ImageTk = None

# Try to import apiscan modules
try:
    from version import __version__
except ImportError:
    __version__ = "5.0.0"

# Regex to strip ANSI escape sequences from colorama output
_re_ansi = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\]8;.*?\x1b\\")

# =============================================================================
# DESIGN SYSTEM - Professional Dark Theme
# =============================================================================
APP_NAME = f"APISCAN v{__version__}"
WINDOW_WIDTH = 1280
WINDOW_HEIGHT = 860
WINDOW_MIN_WIDTH = 1024
WINDOW_MIN_HEIGHT = 700

# Startup banner display size. 900x300 keeps the requested 15:5 ratio.
BANNER_FILE = "apiscan.png"
BANNER_DISPLAY_WIDTH = 900
BANNER_DISPLAY_HEIGHT = 300

# Color palette - Cyber-security dark theme
CLR = {
    "bg_dark":        "#0d1117",
    "bg_card":        "#161b22",
    "bg_input":       "#0d1117",
    "bg_header":      "#010409",
    "bg_output":      "#0d1117",
    "border":         "#30363d",
    "border_focus":   "#58a6ff",
    "text_primary":   "#e6edf3",
    "text_secondary": "#8b949e",
    "text_muted":     "#6e7681",
    "accent":         "#58a6ff",
    "accent_dark":    "#1f6feb",
    "success":        "#3fb950",
    "warning":        "#d29922",
    "danger":         "#f85149",
    "info":           "#79c0ff",
    "purple":         "#a371f7",
    "orange":         "#f0883e",
    "cyan":           "#39d2c0",
}

FONTS = {
    "heading":   ("Segoe UI", 14, "bold"),
    "subheading":("Segoe UI", 11, "bold"),
    "body":      ("Segoe UI", 10),
    "small":     ("Segoe UI", 9),
    "mono":      ("Cascadia Code", 9),
    "mono_sm":   ("Cascadia Code", 8),
    "button":    ("Segoe UI", 10),
    "tab":       ("Segoe UI", 10),
}

AUTH_FLOWS = ["none", "token", "client", "basic", "digest", "ntlm", "auth", "form"]
API_CHECKS = [
    ("API1  - Broken Object Level Authorization (BOLA)",       "api1",  True),
    ("API2  - Broken Authentication",                          "api2",  True),
    ("API3  - Object Property Level Authorization",            "api3",  True),
    ("API4  - Unrestricted Resource Consumption",              "api4",  True),
    ("API5  - Function Level Authorization",                   "api5",  True),
    ("API6  - Sensitive Business Flows",                       "api6",  True),
    ("API7  - Server Side Request Forgery (SSRF)",             "api7",  True),
    ("API8  - Security Misconfiguration",                      "api8",  True),
    ("API9  - Improper Inventory Management",                  "api9",  True),
    ("API10 - Unsafe 3rd-Party API Consumption",               "api10", True),
    ("API11 - AI-assisted OWASP Analysis   ",                  "api11", False),
]


# =============================================================================
# STYLING HELPERS
# =============================================================================
def _init_styles(root: Tk):
    style = ttk.Style()

    # Try clam theme as base (most cross-platform)
    available = style.theme_names()
    if "clam" in available:
        style.theme_use("clam")

    # --- General ---
    style.configure(".", background=CLR["bg_dark"], foreground=CLR["text_primary"])
    style.configure("TFrame", background=CLR["bg_dark"])
    style.configure("Card.TFrame", background=CLR["bg_card"], relief="flat")
    style.configure("Header.TFrame", background=CLR["bg_header"])

    # --- Notebook (tabs) ---
    style.configure("TNotebook", background=CLR["bg_dark"], borderwidth=0)
    style.configure("TNotebook.Tab",
                    background=CLR["bg_card"], foreground=CLR["text_secondary"],
                    padding=[18, 8], font=FONTS["tab"], borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", CLR["bg_dark"])],
              foreground=[("selected", CLR["text_primary"])],
              expand=[("selected", [0, 0, 0, 0])])

    # --- Labels ---
    style.configure("TLabel", background=CLR["bg_dark"], foreground=CLR["text_primary"],
                    font=FONTS["body"])
    style.configure("Card.TLabel", background=CLR["bg_card"], foreground=CLR["text_primary"],
                    font=FONTS["body"])
    style.configure("Muted.TLabel", foreground=CLR["text_muted"], font=FONTS["small"])
    style.configure("Heading.TLabel", font=FONTS["heading"],
                    foreground=CLR["text_primary"], background=CLR["bg_dark"])
    style.configure("Subheading.TLabel", font=FONTS["subheading"],
                    foreground=CLR["accent"], background=CLR["bg_dark"])

    # --- Buttons ---
    style.configure("TButton",
                    background=CLR["border"], foreground=CLR["text_primary"],
                    font=FONTS["button"], borderwidth=0, padding=[14, 6],
                    relief="flat")
    style.map("TButton",
              background=[("active", CLR["accent_dark"]), ("disabled", CLR["bg_card"])],
              foreground=[("active", "#ffffff"), ("disabled", CLR["text_muted"])])

    style.configure("Primary.TButton",
                    background=CLR["accent"], foreground="#ffffff",
                    font=("Segoe UI", 11, "bold"), borderwidth=0, padding=[24, 10])
    style.map("Primary.TButton",
              background=[("active", CLR["accent_dark"]), ("disabled", CLR["bg_card"])],
              foreground=[("disabled", CLR["text_muted"])])

    style.configure("Danger.TButton",
                    foreground=CLR["danger"], font=("Segoe UI", 11, "bold"),
                    padding=[24, 10])
    style.map("Danger.TButton",
              background=[("active", "#3d1214")])

    style.configure("Small.TButton",
                    font=FONTS["small"], padding=[8, 3])

    # --- Entries ---
    style.configure("TEntry",
                    fieldbackground=CLR["bg_input"], foreground=CLR["text_primary"],
                    borderwidth=1, relief="solid", padding=[8, 5],
                    insertcolor=CLR["text_primary"])
    style.map("TEntry",
              fieldbackground=[("focus", CLR["bg_input"])],
              bordercolor=[("focus", CLR["border_focus"])])

    # Ensure cursor is visible on dark backgrounds (global fallback)
    root.option_add("*TEntry.insertBackground", CLR["text_primary"])
    root.option_add("*Entry.insertBackground", CLR["text_primary"])
    root.option_add("*Text.insertBackground", CLR["text_primary"])

    # --- Combobox ---
    style.configure("TCombobox",
                    fieldbackground=CLR["bg_input"], foreground=CLR["text_primary"],
                    background=CLR["bg_input"], arrowcolor=CLR["text_primary"],
                    borderwidth=1, relief="solid", padding=[6, 4])
    style.map("TCombobox",
              fieldbackground=[("readonly", CLR["bg_input"]), ("focus", CLR["bg_input"])])

    # --- Checkbuttons ---
    style.configure("TCheckbutton",
                    background=CLR["bg_dark"], foreground=CLR["text_primary"],
                    font=FONTS["body"])
    style.map("TCheckbutton",
              background=[("active", CLR["bg_dark"])])

    style.configure("Card.TCheckbutton",
                    background=CLR["bg_card"], foreground=CLR["text_primary"],
                    font=FONTS["body"])
    style.map("Card.TCheckbutton",
              background=[("active", CLR["bg_card"])])

    # --- Separator ---
    style.configure("TSeparator", background=CLR["border"])

    # --- Progressbar ---
    style.configure("TProgressbar",
                    background=CLR["accent"], troughcolor=CLR["bg_card"],
                    borderwidth=0, thickness=6)

    # --- LabelFrame ---
    style.configure("TLabelframe", background=CLR["bg_card"], foreground=CLR["text_primary"],
                    borderwidth=1, relief="solid", bordercolor=CLR["border"])
    style.configure("TLabelframe.Label", background=CLR["bg_card"],
                    foreground=CLR["accent"], font=FONTS["subheading"])

    # --- PanedWindow ---
    style.configure("TPanedwindow", background=CLR["border"])

    # --- Scrollbar ---
    style.configure("TScrollbar", background=CLR["bg_card"], troughcolor=CLR["bg_dark"],
                    borderwidth=0, arrowsize=14)
    style.map("TScrollbar",
              background=[("active", CLR["border"])])

    return style


def _make_card(parent: ttk.Frame, title: str = "") -> ttk.Frame:
    card = ttk.Frame(parent, style="Card.TFrame", padding=2)
    if title:
        lbl = ttk.Label(card, text=title, style="Subheading.TLabel")
        lbl.pack(anchor=W, padx=14, pady=(12, 6))
    card.content = ttk.Frame(card, style="Card.TFrame")
    card.content.pack(fill="both", expand=True, padx=1, pady=1)
    return card


# =============================================================================
# MAIN APPLICATION CLASS
# =============================================================================
class APISCANApp:

    def __init__(self, root: Tk):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.minsize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        self.root.configure(bg=CLR["bg_dark"])

        # Queue for thread-safe communication
        self.text_queue: queue.Queue = queue.Queue()
        self.scan_thread: threading.Thread | None = None
        self.running = False
        self.scan_process: subprocess.Popen | None = None

        # All StringVar / BooleanVar
        self.url_var = StringVar()
        self.swagger_var = StringVar()
        self.crawl_var = BooleanVar(value=False)
        self.crawl_depth_var = StringVar(value="3")
        self.crawl_aggressive_var = BooleanVar(value=False)
        self.crawl_passive_var = BooleanVar(value=False)
        self.crawl_validate_var = BooleanVar(value=True)
        self.crawl_validate_workers_var = StringVar(value="8")
        self.crawl_validate_mode_var = StringVar(value="balanced")
        self.threads_var = StringVar(value="16")
        self.timeout_var = StringVar(value="5.0")
        self.proxy_var = StringVar()
        self.insecure_var = BooleanVar(value=False)
        self.debug_var = BooleanVar(value=False)
        self.dummy_var = BooleanVar(value=False)
        self.plan_only_var = BooleanVar(value=False)
        self.flow_var = StringVar(value="none")
        self.token_var = StringVar()
        self.basic_auth_var = StringVar()
        self.apikey_var = StringVar()
        self.apikey_header_var = StringVar(value="X-API-Key")
        self.ntlm_var = StringVar()
        self.client_id_var = StringVar()
        self.client_secret_var = StringVar()
        self.token_url_var = StringVar()
        self.auth_url_var = StringVar()
        self.redirect_uri_var = StringVar()
        self.scope_var = StringVar()
        self.client_cert_var = StringVar()
        self.client_key_var = StringVar()
        self.cert_password_var = StringVar()
        # Form auto-login
        self.form_login_url_var = StringVar()
        self.form_login_user_var = StringVar()
        self.form_login_pass_var = StringVar()
        self.form_login_token_path_var = StringVar()
        self.headers_file_var = StringVar()
        self.ids_file_var = StringVar()
        self.api_vars: dict[str, BooleanVar] = {}

        # -- Advanced / extra CLI settings --
        self.db_path_var = StringVar()
        self.plan_then_scan_var = BooleanVar(value=False)
        self.verify_plan_var = BooleanVar(value=False)
        self.success_codes_var = StringVar(value="200-299")
        self.retry500_var = StringVar(value="1")
        self.no_retry_500_var = BooleanVar(value=False)
        self.export_vars_var = StringVar()
        self.rewrite_var = StringVar()
        self.no_sanitize_var = BooleanVar(value=False)
        self.api3_active_var = BooleanVar(value=False)
        self.normalize_version_var = BooleanVar(value=False)
        self.no_normalize_version_var = BooleanVar(value=False)
        self.deep_scan_var = BooleanVar(value=False)   # APISCAN_DEEP_SCAN
        self.fast_mode_var = BooleanVar(value=True)    # APISCAN_FAST (default on)
        self.intensity_var = StringVar(value="medium")  # APISCAN_INTENSITY
        self.chain_mode_var = BooleanVar(value=False)   # --chain-mode
        self.chain_depth_var = StringVar(value="1")     # --chain-depth

        self._build_ui()
        self._poll_queue()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # =========================================================================
    # UI CONSTRUCTION
    # =========================================================================
    def _build_ui(self):
        root_frame = ttk.Frame(self.root, style="Root.TFrame")
        root_frame.pack(fill="both", expand=True)

        # --- Header bar ---
        self._build_header(root_frame)

        # --- Main content ---
        content = ttk.Frame(root_frame, style="Root.TFrame")
        content.pack(fill="both", expand=True, padx=12, pady=(4, 6))
        content.rowconfigure(0, weight=35, minsize=200)  # settings
        content.rowconfigure(1, weight=65, minsize=300)  # output  never below 300 px
        content.columnconfigure(0, weight=1)

        # Settings pane
        top = ttk.Frame(content, style="Root.TFrame")
        top.grid(row=0, column=0, sticky="nsew")

        self._build_settings_panel(top)

        # Output pane (hidden on non-Target tabs, shown on Target)
        self._output_frame = ttk.Frame(content, style="Root.TFrame")
        self._output_frame.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        self._content_grid = content

        self._build_output_panel(self._output_frame)

        self._build_statusbar(root_frame)

        # Welcome with banner image visible
        self._log("  APISCAN GUI ready.", "header")
        self._log("  Configure target URL, select API scans, and press START SCAN.\n", "info")
        self._show_banner()

    def _build_header(self, parent: ttk.Frame):
        header = ttk.Frame(parent, style="Header.TFrame", height=64)
        header.pack(fill="x")
        header.pack_propagate(False)

        title_frame = ttk.Frame(header, style="Header.TFrame")
        title_frame.pack(side="left", padx=16, pady=4)

        # Line 1: APISCAN name + version
        row1 = ttk.Frame(title_frame, style="Header.TFrame")
        row1.pack(anchor=W)
        ttk.Label(row1, text="APISCAN",
                  font=("Segoe UI", 17, "bold"),
                  foreground=CLR["accent"],
                  background=CLR["bg_header"]).pack(side="left")
        ttk.Label(row1, text=f"  v{__version__}",
                  font=("Segoe UI", 11),
                  foreground=CLR["text_secondary"],
                  background=CLR["bg_header"]).pack(side="left")
        ttk.Label(row1, text="  \u2014  API Security Scanner",
                  font=FONTS["small"],
                  foreground=CLR["text_muted"],
                  background=CLR["bg_header"]).pack(side="left")

        # Line 2: License + Author (match apiscan.py header)
        row2 = ttk.Frame(title_frame, style="Header.TFrame")
        row2.pack(anchor=W, pady=(2, 0))
        ttk.Label(row2, text="Licensed under the AGPL-v3.0 License",
                  font=("Segoe UI", 8),
                  foreground=CLR["text_muted"],
                  background=CLR["bg_header"]).pack(side="left")
        ttk.Label(row2, text="  \u00b7  Author: Perry Mertens  \u00b7  pamsniffer@gmail.com  \u00b7  \u00a9 2026",
                  font=("Segoe UI", 8),
                  foreground=CLR["text_muted"],
                  background=CLR["bg_header"]).pack(side="left")

        # --- Big START button in the header ---
        btn_frame = ttk.Frame(header, style="Header.TFrame")
        btn_frame.pack(side="right", padx=12, pady=6)

        self.header_scan_btn = ttk.Button(
            btn_frame, text="START SCAN",
            command=self._start_scan,
            style="Primary.TButton"
        )
        self.header_scan_btn.pack(side="left", padx=(0, 6))

        self.header_stop_btn = ttk.Button(
            btn_frame, text="STOP",
            command=self._stop_scan,
            style="Danger.TButton", state=DISABLED
        )
        self.header_stop_btn.pack(side="left")

        self.header_status = ttk.Label(header,
                                       text="\u25cf Ready",
                                       font=FONTS["small"],
                                       foreground=CLR["text_muted"],
                                       background=CLR["bg_header"])
        self.header_status.pack(side="right", padx=16)

    def _build_statusbar(self, parent: ttk.Frame):
        statusbar = ttk.Frame(parent, style="Header.TFrame", height=24)
        statusbar.pack(fill="x")
        statusbar.pack_propagate(False)

        self.status_text = ttk.Label(statusbar, text="Ready - Configure target and press Start Scan",
                                     font=FONTS["small"], foreground=CLR["text_muted"],
                                     background=CLR["bg_header"])
        self.status_text.pack(side="left", padx=12, pady=2)

        self.progress_bar = ttk.Progressbar(statusbar, mode="indeterminate", length=160)
        self.progress_bar.pack(side="right", padx=12, pady=2)

    def _build_settings_panel(self, parent: ttk.Frame):
        # Canvas + scrollbar for vertical scrolling
        canvas = Canvas(parent, bg=CLR["bg_dark"], highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        inner = ttk.Frame(canvas, style="Root.TFrame")
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win_id, width=e.width))

        # Mousewheel scroll
        def _mw(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", _mw))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

        # --- Notebook inside the scrollable area ---
        notebook = ttk.Notebook(inner)
        notebook.pack(fill="x", expand=False, pady=(0, 2))

        # Tab 1: Target
        tab_target = ttk.Frame(notebook, style="Root.TFrame")
        notebook.add(tab_target, text="  Target  ")
        self._build_tab_target(tab_target)

        # Tab 2: Authentication
        tab_auth = ttk.Frame(notebook, style="Root.TFrame")
        notebook.add(tab_auth, text="  Authentication  ")
        self._build_tab_auth(tab_auth)

        # Tab 3: Form Login
        tab_form = ttk.Frame(notebook, style="Root.TFrame")
        notebook.add(tab_form, text="  Form Login  ")
        self._build_tab_form_login(tab_form)

        # Tab 4: Scans
        tab_scans = ttk.Frame(notebook, style="Root.TFrame")
        notebook.add(tab_scans, text="  OWASP Scans  ")
        self._build_tab_scans(tab_scans)

        # Tab 5: Advanced
        tab_advanced = ttk.Frame(notebook, style="Root.TFrame")
        notebook.add(tab_advanced, text="  Advanced  ")
        self._build_tab_advanced(tab_advanced)

        # --- Action bar ---
        action_bar = ttk.Frame(inner, style="Root.TFrame")
        action_bar.pack(fill="x", pady=(12, 6))

        self.scan_btn = ttk.Button(action_bar, text="START SCAN",
                                   command=self._start_scan,
                                   style="Primary.TButton")
        self.scan_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = ttk.Button(action_bar, text="STOP",
                                   command=self._stop_scan,
                                   style="Danger.TButton", state=DISABLED)
        self.stop_btn.pack(side="left")

        ttk.Button(action_bar, text="Clear Output", style="Small.TButton",
                   command=self._clear_output).pack(side="right", padx=4)
        ttk.Button(action_bar, text="Open Reports", style="Small.TButton",
                   command=self._open_output_folder).pack(side="right", padx=4)

        # --- Tab-switch: full screen for non-Target, split for Target ---
        self._notebook = notebook
        notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        # Start on Target - show split
        self.root.after(50, lambda: self._on_tab_changed(force_target=True))

    def _on_tab_changed(self, event=None, force_target=False):
        try:
            idx = self._notebook.index("current") if not force_target else 0
        except Exception:
            idx = 0
        # Tab 0 = Target
        if idx == 0:
            self._content_grid.rowconfigure(0, weight=20, minsize=120)
            self._content_grid.rowconfigure(1, weight=80, minsize=300)
            self._output_frame.grid()
        else:
            self._content_grid.rowconfigure(0, weight=1, minsize=100)
            self._content_grid.rowconfigure(1, weight=0, minsize=0)
            self._output_frame.grid_remove()

    # =========================== TAB: TARGET ================================
    def _build_tab_target(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)

        # --- Card: Connection ---
        card1 = _make_card(parent, "Connection Settings")
        card1.pack(fill="x", padx=10, pady=(10, 6))
        inner = card1.content
        inner.columnconfigure(0, weight=1)

        url_frame = ttk.Frame(inner, style="Card.TFrame")
        url_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=(8, 4))
        ttk.Label(url_frame, text="Target URL *", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        self.url_entry = ttk.Entry(url_frame, font=FONTS["body"])
        self.url_entry.pack(side="left", fill="x", expand=True)
        ttk.Label(url_frame, text="https://api.example.com",
                  style="Muted.TLabel").pack(side="left", padx=(6, 0))
        self.url_entry.configure(textvariable=self.url_var)

        sw_frame = ttk.Frame(inner, style="Card.TFrame")
        sw_frame.grid(row=1, column=0, sticky="ew", padx=14, pady=4)
        ttk.Label(sw_frame, text="Swagger / OpenAPI", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        sw_entry = ttk.Entry(sw_frame, textvariable=self.swagger_var, font=FONTS["body"])
        sw_entry.pack(side="left", fill="x", expand=True)
        ttk.Label(sw_frame, text="*.json *.yaml", style="Muted.TLabel").pack(
            side="left", padx=(6, 0))
        ttk.Button(sw_frame, text="...", width=3, style="Small.TButton",
                   command=self._browse_swagger).pack(side="left", padx=(4, 0))

        ttk.Separator(inner, orient=HORIZONTAL).grid(
            row=2, column=0, sticky="ew", padx=14, pady=8)

        # Crawl options
        ttk.Checkbutton(inner, text="Auto-discovery via crawling (--crawl)",
                        variable=self.crawl_var,
                        style="Card.TCheckbutton").grid(
            row=3, column=0, sticky=W, padx=14, pady=2)

        crawl_frame = ttk.Frame(inner, style="Card.TFrame")
        crawl_frame.grid(row=4, column=0, sticky="ew", padx=40, pady=2)
        ttk.Label(crawl_frame, text="Depth", style="Card.TLabel").pack(side="left", padx=(0, 6))
        depth_entry = ttk.Entry(crawl_frame, textvariable=self.crawl_depth_var,
                                width=5, font=FONTS["body"])
        depth_entry.pack(side="left")
        ttk.Label(crawl_frame, text="(1-10)", style="Muted.TLabel").pack(
            side="left", padx=(6, 12))
        ttk.Checkbutton(crawl_frame, text="Aggressive",
                        variable=self.crawl_aggressive_var,
                        style="Card.TCheckbutton").pack(side="left", padx=4)
        ttk.Checkbutton(crawl_frame, text="Passive",
                        variable=self.crawl_passive_var,
                        style="Card.TCheckbutton").pack(side="left", padx=4)

        # Crawl validation
        crawl_val_frame = ttk.Frame(inner, style="Card.TFrame")
        crawl_val_frame.grid(row=5, column=0, sticky="ew", padx=40, pady=(4, 2))
        ttk.Checkbutton(crawl_val_frame, text="Validate endpoints (--crawl-validate)",
                        variable=self.crawl_validate_var,
                        style="Card.TCheckbutton").pack(side="left")
        ttk.Label(crawl_val_frame, text="  Mode:", style="Card.TLabel").pack(side="left", padx=(12, 4))
        mode_menu = ttk.Combobox(crawl_val_frame, textvariable=self.crawl_validate_mode_var,
                                 values=["balanced", "strict"], state="readonly",
                                 width=10, font=FONTS["small"])
        mode_menu.pack(side="left")
        ttk.Label(crawl_val_frame, text="  Workers:", style="Card.TLabel").pack(side="left", padx=(12, 4))
        ttk.Entry(crawl_val_frame, textvariable=self.crawl_validate_workers_var,
                  width=4, font=FONTS["small"]).pack(side="left")

        ttk.Separator(inner, orient=HORIZONTAL).grid(
            row=6, column=0, sticky="ew", padx=14, pady=8)

        # Plan checkbox
        ttk.Checkbutton(inner, text="Plan only - build request CSV without sending (--plan-only)",
                        variable=self.plan_only_var,
                        style="Card.TCheckbutton").grid(
            row=7, column=0, sticky=W, padx=14, pady=2)

        # --- Compact: Additional files inline ---
        add_files_frame = ttk.Frame(inner, style="Card.TFrame")
        add_files_frame.grid(row=8, column=0, sticky="ew", padx=14, pady=(6, 4))
        ttk.Label(add_files_frame, text="Headers File", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(add_files_frame, textvariable=self.headers_file_var, width=28).pack(side="left")
        ttk.Button(add_files_frame, text="...", width=3, style="Small.TButton",
                   command=lambda: self._browse_file("headers_file_var", "*.json")
                   ).pack(side="left", padx=(2, 10))
        ttk.Label(add_files_frame, text="IDs File", style="Card.TLabel").pack(side="left", padx=(0, 6))
        ttk.Entry(add_files_frame, textvariable=self.ids_file_var, width=28).pack(side="left")
        ttk.Button(add_files_frame, text="...", width=3, style="Small.TButton",
                   command=lambda: self._browse_file("ids_file_var", "*.json")
                   ).pack(side="left", padx=(2, 0))

    # =========================== TAB: AUTH ==================================
    def _build_tab_auth(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=1)

        # --- Card: Auth Method ---
        card1 = _make_card(parent, "Authentication Method")
        card1.pack(fill="x", padx=10, pady=(10, 6))
        inner = card1.content
        inner.columnconfigure(0, weight=1)

        flow_frame = ttk.Frame(inner, style="Card.TFrame")
        flow_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=6)
        ttk.Label(flow_frame, text="Auth Flow", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        flow_menu = ttk.Combobox(flow_frame, textvariable=self.flow_var,
                                 values=AUTH_FLOWS, state="readonly",
                                 width=14, font=FONTS["body"])
        flow_menu.pack(side="left")
        flow_menu.set("none")
        ttk.Label(flow_frame, text="Select authentication type",
                  style="Muted.TLabel").pack(side="left", padx=(10, 0))

        # Instruction hint
        hint_frame = ttk.Frame(inner, style="Card.TFrame")
        hint_frame.grid(row=1, column=0, sticky="ew", padx=14, pady=(2, 4))
        self.auth_hint = ttk.Label(
            hint_frame,
            text="  Token flow:   fill the Bearer Token field below",
            style="Muted.TLabel"
        )
        self.auth_hint.pack(anchor=W)

        # Bearer token
        tok_frame = ttk.Frame(inner, style="Card.TFrame")
        tok_frame.grid(row=2, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(tok_frame, text="Bearer Token", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        self.token_entry = ttk.Entry(tok_frame, textvariable=self.token_var,
                                     show="*", font=FONTS["body"])
        self.token_entry.pack(side="left", fill="x", expand=True)
        ttk.Label(tok_frame, text="JWT / API token", style="Muted.TLabel").pack(
            side="left", padx=(6, 0))
        ttk.Button(tok_frame, text="Show", width=5, style="Small.TButton",
                   command=lambda: self._toggle_show(self.token_entry)
                   ).pack(side="left", padx=(4, 0))

        # Basic Auth
        basic_frame = ttk.Frame(inner, style="Card.TFrame")
        basic_frame.grid(row=3, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(basic_frame, text="Basic Auth", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        self.basic_entry = ttk.Entry(basic_frame, textvariable=self.basic_auth_var,
                                     show="*", font=FONTS["body"])
        self.basic_entry.pack(side="left", fill="x", expand=True)
        ttk.Label(basic_frame, text="user:password", style="Muted.TLabel").pack(
            side="left", padx=(6, 0))
        ttk.Button(basic_frame, text="Show", width=5, style="Small.TButton",
                   command=lambda: self._toggle_show(self.basic_entry)
                   ).pack(side="left", padx=(4, 0))

        # API Key
        api_frame = ttk.Frame(inner, style="Card.TFrame")
        api_frame.grid(row=4, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(api_frame, text="API Key", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        self.apikey_entry = ttk.Entry(api_frame, textvariable=self.apikey_var,
                                      show="*", font=FONTS["body"])
        self.apikey_entry.pack(side="left", fill="x", expand=True)
        ttk.Label(api_frame, text="Header:", style="Card.TLabel").pack(
            side="left", padx=(8, 4))
        ttk.Entry(api_frame, textvariable=self.apikey_header_var,
                  width=14, font=FONTS["body"]).pack(side="left")
        ttk.Button(api_frame, text="Show", width=5, style="Small.TButton",
                   command=lambda: self._toggle_show(self.apikey_entry)
                   ).pack(side="left", padx=(4, 0))

        # NTLM
        ntlm_frame = ttk.Frame(inner, style="Card.TFrame")
        ntlm_frame.grid(row=5, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(ntlm_frame, text="NTLM", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        self.ntlm_entry = ttk.Entry(ntlm_frame, textvariable=self.ntlm_var,
                                    show="*", font=FONTS["body"])
        self.ntlm_entry.pack(side="left", fill="x", expand=True)
        ttk.Label(ntlm_frame, text="DOMAIN\\user:password", style="Muted.TLabel").pack(
            side="left", padx=(6, 0))
        ttk.Button(ntlm_frame, text="Show", width=5, style="Small.TButton",
                   command=lambda: self._toggle_show(self.ntlm_entry)
                   ).pack(side="left", padx=(4, 0))

        # --- Card: OAuth2 ---
        card2 = _make_card(parent, "OAuth2 / OpenID Connect")
        card2.pack(fill="x", padx=10, pady=6)
        inner2 = card2.content
        inner2.columnconfigure(0, weight=1)

        oa_row1 = ttk.Frame(inner2, style="Card.TFrame")
        oa_row1.grid(row=0, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(oa_row1, text="Client ID", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        cid_entry = ttk.Entry(oa_row1, textvariable=self.client_id_var,
                              font=FONTS["body"])
        cid_entry.pack(side="left", fill="x", expand=True)
        ttk.Label(oa_row1, text="Client Secret", style="Card.TLabel").pack(
            side="left", padx=(16, 8))
        secret = ttk.Entry(oa_row1, textvariable=self.client_secret_var,
                           show="*", width=24, font=FONTS["body"])
        secret.pack(side="left")

        oa_row2 = ttk.Frame(inner2, style="Card.TFrame")
        oa_row2.grid(row=1, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(oa_row2, text="Token URL", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(oa_row2, textvariable=self.token_url_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Label(oa_row2, text="Auth URL", style="Card.TLabel").pack(
            side="left", padx=(16, 8))
        ttk.Entry(oa_row2, textvariable=self.auth_url_var,
                  width=28, font=FONTS["body"]).pack(side="left")

        oa_row3 = ttk.Frame(inner2, style="Card.TFrame")
        oa_row3.grid(row=2, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(oa_row3, text="Redirect URI", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(oa_row3, textvariable=self.redirect_uri_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Label(oa_row3, text="Scope", style="Card.TLabel").pack(
            side="left", padx=(16, 8))
        ttk.Entry(oa_row3, textvariable=self.scope_var, width=22,
                  font=FONTS["body"]).pack(side="left")

        # --- Card: mTLS ---
        card3 = _make_card(parent, "Mutual TLS (mTLS)")
        card3.pack(fill="x", padx=10, pady=6)
        inner3 = card3.content
        inner3.columnconfigure(0, weight=1)

        mtls1 = ttk.Frame(inner3, style="Card.TFrame")
        mtls1.grid(row=0, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(mtls1, text="Client Cert", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(mtls1, textvariable=self.client_cert_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Button(mtls1, text="...", width=3, style="Small.TButton",
                   command=lambda: self._browse_file("client_cert_var", "*.pem *.crt")
                   ).pack(side="left", padx=(4, 0))

        mtls2 = ttk.Frame(inner3, style="Card.TFrame")
        mtls2.grid(row=1, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(mtls2, text="Client Key", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(mtls2, textvariable=self.client_key_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Button(mtls2, text="...", width=3, style="Small.TButton",
                   command=lambda: self._browse_file("client_key_var", "*.pem *.key")
                   ).pack(side="left", padx=(4, 0))

        mtls3 = ttk.Frame(inner3, style="Card.TFrame")
        mtls3.grid(row=2, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(mtls3, text="Cert Password", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        pwd = ttk.Entry(mtls3, textvariable=self.cert_password_var,
                        show="*", width=32, font=FONTS["body"])
        pwd.pack(side="left")

        # --- Dynamic hint: update when flow changes ---
        self.flow_var.trace_add("write", self._on_flow_changed)

    def _on_flow_changed(self, *_):
        hints = {
            "none":   "  No authentication will be used",
            "token":  "  Token flow:   fill the Bearer Token field above",
            "client": "  OAuth2 Client Credentials:   fill Client ID & Secret below",
            "basic":  "  Basic Auth:   fill user:password in the Basic Auth field above",
            "digest": "  Digest Auth:   fill user:password in the Basic Auth field above",
            "ntlm":   "  NTLM Auth:   fill DOMAIN\\user:password in the NTLM field above",
            "auth":   "  OAuth2 Authorization Code:   fill Client ID, Secret, and Auth URL below",
            "form":   "  Form Auto-Login:   switch to the 'Form Login' tab and fill credentials",
        }
        flow = self.flow_var.get().strip().lower()
        self.auth_hint.configure(text=hints.get(flow, hints["none"]))

    # =========================== TAB: FORM LOGIN ===========================
    def _build_tab_form_login(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=1)

        # ── Step 1 card: where is the login page? ──
        card1 = _make_card(parent, "Step 1 — Where is the login page?")
        card1.pack(fill="x", padx=10, pady=(10, 4))
        c1 = card1.content
        c1.columnconfigure(0, weight=1)

        ttk.Label(c1, text=(
            "Paste a login page URL, or leave empty and the scanner will find it automatically "
            "using the swagger spec + common paths."
        ), style="Muted.TLabel", wraplength=600).grid(
            row=0, column=0, sticky="ew", padx=14, pady=(4, 6))

        row1 = ttk.Frame(c1, style="Card.TFrame")
        row1.grid(row=1, column=0, sticky="ew", padx=14, pady=2)
        ttk.Label(row1, text="Login URL", style="Card.TLabel",
                  width=14, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(row1, textvariable=self.form_login_url_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)

        self.form_detect_btn = ttk.Button(
            row1, text="Auto-Detect", style="Small.TButton",
            command=self._detect_form_fields
        )
        self.form_detect_btn.pack(side="left", padx=(8, 0))

        # Result line
        self.form_detect_label = ttk.Label(
            c1, text="Click 'Auto-Detect' to find the login endpoint — or enter a URL manually.",
            style="Muted.TLabel", wraplength=600
        )
        self.form_detect_label.grid(row=2, column=0, sticky="ew", padx=14, pady=(6, 6))

        # ── Step 2 card: credentials ──
        card2 = _make_card(parent, "Step 2 — Enter credentials")
        card2.pack(fill="x", padx=10, pady=4)
        c2 = card2.content
        c2.columnconfigure(0, weight=1)

        ttk.Label(c2, text="Your login details. The scanner will try common field names "
                  "(email, username, password) automatically.",
                  style="Muted.TLabel", wraplength=600).grid(
            row=0, column=0, sticky="ew", padx=14, pady=(4, 6))

        row2a = ttk.Frame(c2, style="Card.TFrame")
        row2a.grid(row=1, column=0, sticky="ew", padx=14, pady=2)
        ttk.Label(row2a, text="Username / Email", style="Card.TLabel",
                  width=14, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(row2a, textvariable=self.form_login_user_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)

        row2b = ttk.Frame(c2, style="Card.TFrame")
        row2b.grid(row=2, column=0, sticky="ew", padx=14, pady=2)
        ttk.Label(row2b, text="Password", style="Card.TLabel",
                  width=14, anchor=E).pack(side="left", padx=(0, 8))
        self._form_pass_entry = ttk.Entry(row2b, textvariable=self.form_login_pass_var,
                                          show="*", font=FONTS["body"])
        self._form_pass_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(row2b, text="Show", width=5, style="Small.TButton",
                   command=lambda: self._toggle_show(self._form_pass_entry)
                   ).pack(side="left", padx=(4, 0))

        # ── Step 3 card: token extraction (optional) ──
        card3 = _make_card(parent, "Step 3 — Token extraction (optional)")
        card3.pack(fill="x", padx=10, pady=4)
        c3 = card3.content
        c3.columnconfigure(0, weight=1)

        ttk.Label(c3, text="If the scanner can't find the token automatically, "
                  "tell it where to look in the JSON response.",
                  style="Muted.TLabel", wraplength=600).grid(
            row=0, column=0, sticky="ew", padx=14, pady=(4, 6))

        row3 = ttk.Frame(c3, style="Card.TFrame")
        row3.grid(row=1, column=0, sticky="ew", padx=14, pady=2)
        ttk.Label(row3, text="Token JSON path", style="Card.TLabel",
                  width=14, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(row3, textvariable=self.form_login_token_path_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Label(row3, text='e.g.  authentication.token  or  data.access_token',
                  style="Muted.TLabel").pack(side="left", padx=(6, 0))

        # ── Quick summary ──
        self.form_summary_label = ttk.Label(
            parent, text="", style="Muted.TLabel", wraplength=600
        )
        self.form_summary_label.pack(fill="x", padx=14, pady=(4, 0))

        # Auto-switch Auth Flow to "form" when credentials are filled in
        def _auto_flow_form(*_):
            if self.form_login_user_var.get().strip() and self.form_login_pass_var.get().strip():
                if self.flow_var.get() != "form":
                    self.flow_var.set("form")
        self.form_login_user_var.trace_add("write", _auto_flow_form)
        self.form_login_pass_var.trace_add("write", _auto_flow_form)

    def _detect_form_fields(self):
        import requests
        from urllib.parse import urljoin, urlsplit

        self.form_detect_btn.configure(state=DISABLED, text="Working...")
        self.form_detect_label.configure(text="Searching for login endpoint...", foreground=CLR["info"])
        self.form_summary_label.configure(text="")

        try:
            base_url = self.url_var.get().strip()
            login_url = self.form_login_url_var.get().strip()

            # Clean up SPA hash fragments
            if login_url and "#" in login_url:
                p = urlsplit(login_url)
                clean = p._replace(fragment="").geturl()
                if clean != login_url:
                    self.form_login_url_var.set(clean)
                    login_url = clean

            # ── Step 1: "Learn by trying" — POST dummy creds to discover everything ──
            COMMON_PATHS = [
                "/rest/user/login",
                "/api/auth/login",
                "/identity/api/auth/login",
                "/b2b/v2/authentication/login",
                "/users/v1/login",
                "/api/login",
                "/api/v1/login",
                "/auth/login",
                "/login",         # HTML form — keep last, API endpoints first
            ]
            CRED_COMBOS = [
                {"email": "dummy@test.com", "password": "dummy"},
                {"username": "dummy", "password": "dummy"},
                {"user": "dummy", "password": "dummy"},
                {"login": "dummy", "password": "dummy"},
            ]
            TOKEN_PATHS = [
                "authentication.token", "authentication.access_token",
                "token", "access_token", "accessToken", "jwt",
                "data.token", "data.access_token", "id_token",
            ]

            api_url = None
            detected_fields = None
            detected_token_path = None
            detected_auth_type = None  # "bearer", "cookie", "header"

            sess = requests.Session()
            if self.insecure_var.get():
                sess.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Use user-provided URL first, but NEVER the bare base URL
            paths_to_try: list[str] = []
            if login_url and login_url.rstrip("/") != base_url.rstrip("/"):
                # User gave a specific path — try it first
                paths_to_try.append(login_url)
            # Always try common API paths (these are the real endpoints)
            paths_to_try += [urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
                           for p in COMMON_PATHS]

            for url in paths_to_try:
                if api_url:
                    break
                for creds in CRED_COMBOS:
                    try:
                        r = sess.post(url, json=creds, timeout=5, allow_redirects=False)
                    except Exception:
                        continue

                    # Check response for clues
                    if r.status_code in (200, 201):
                        ct = (r.headers.get("Content-Type") or "").lower()
                        # Skip HTML pages — those are web forms, not API endpoints
                        if "text/html" in ct:
                            continue
                        # Success — analyze what we got
                        detected_fields = creds
                        api_url = url
                        detected_auth_type = "bearer"  # assume Bearer token

                        # Look for token in JSON body
                        if "application/json" in ct:
                            try:
                                data = r.json()
                                if isinstance(data, dict):
                                    for tp in TOKEN_PATHS:
                                        node = data
                                        for seg in tp.split("."):
                                            node = node.get(seg) if isinstance(node, dict) else None
                                            if node is None:
                                                break
                                        if node and isinstance(node, str) and len(node) > 10:
                                            detected_token_path = tp
                                            break
                                    # Also check Set-Cookie
                                    if r.headers.get("Set-Cookie"):
                                        detected_auth_type = "cookie"
                            except Exception:
                                pass
                        break

                    elif r.status_code == 401:
                        # Unauthorized — but endpoint exists and expects these fields
                        api_url = url
                        detected_fields = creds
                        detected_auth_type = "bearer"
                        break

                    elif r.status_code in (400, 422):
                        # Bad request / validation error — endpoint exists
                        api_url = url
                        detected_fields = creds
                        detected_auth_type = "bearer"
                        break

                    elif r.status_code in (301, 302, 303):
                        # Redirect — maybe it redirects to a token page
                        api_url = url
                        detected_fields = creds
                        detected_auth_type = "cookie"
                        break

            # ── Step 1b: Also try form-encoded POST (not JSON) ──
            if not api_url:
                for url in paths_to_try:
                    if api_url:
                        break
                    for creds in CRED_COMBOS:
                        try:
                            r = sess.post(url, data=creds, timeout=5, allow_redirects=False)
                            ct_fb = (r.headers.get("Content-Type") or "").lower()
                            if r.status_code in (200, 201, 301, 302, 303, 400, 401, 422) and "text/html" not in ct_fb:
                                api_url = url
                                detected_fields = creds
                                detected_auth_type = "cookie" if r.status_code in (301, 302) else "bearer"
                                break
                        except Exception:
                            continue

            # ── Step 1c: Try the swagger-based discover_login_url as last resort ──
            if not api_url and base_url:
                try:
                    from form_login import discover_login_url
                    import argparse
                except ImportError:
                    discover_login_url = None
                if discover_login_url:
                    ns = argparse.Namespace(
                        swagger=self.swagger_var.get().strip() or None,
                        url=base_url,
                    )
                    api_url = discover_login_url(ns, sess, base_url)

            if api_url:
                self.form_login_url_var.set(api_url)
                parts = [f"Found: {api_url}"]
                if detected_fields:
                    keys = [k for k in detected_fields if k != "password"]
                    parts.append(f"fields: {', '.join(keys)} + password")
                if detected_token_path:
                    parts.append(f"token: {detected_token_path}")
                    self.form_login_token_path_var.set(detected_token_path)
                if detected_auth_type:
                    parts.append(f"auth: {detected_auth_type}")
                self.form_detect_label.configure(
                    text=" | ".join(parts),
                    foreground=CLR["success"]
                )
                self.form_summary_label.configure(
                    text=" Ready — the scanner learned the login mechanism from the server response.",
                    foreground=CLR["info"]
                )
                self.form_detect_btn.configure(state=NORMAL, text="Auto-Detect")
                return

            # ── Step 2: Fall back to HTML form parsing ──
            if not login_url:
                self.form_detect_label.configure(
                    text="No login endpoint found. Enter the URL manually.",
                    foreground=CLR["warning"]
                )
                self.form_summary_label.configure(
                    text="Tip: Juice Shop = /rest/user/login, crAPI = /identity/api/auth/login",
                    foreground=CLR["info"]
                )
                self.form_detect_btn.configure(state=NORMAL, text="Auto-Detect")
                return

            sess2 = requests.Session()
            if self.insecure_var.get():
                sess2.verify = False
            resp = sess2.get(login_url, timeout=10, allow_redirects=True)
            ct = (resp.headers.get("Content-Type") or "").lower()

            if "application/json" in ct:
                self.form_detect_label.configure(
                    text=f"Found JSON endpoint: {login_url}",
                    foreground=CLR["success"]
                )
                self.form_summary_label.configure(
                    text=" JSON API — ready to POST credentials.",
                    foreground=CLR["info"]
                )
            elif "text/html" in ct:
                try:
                    from bs4 import BeautifulSoup
                except ImportError:
                    self.form_detect_label.configure(
                        text="Install beautifulsoup4: pip install beautifulsoup4",
                        foreground=CLR["warning"]
                    )
                    self.form_detect_btn.configure(state=NORMAL, text="Auto-Detect")
                    return

                soup = BeautifulSoup(resp.text, "html.parser")
                forms = soup.find_all("form")
                login_form = None
                for f in forms:
                    if f.find("input", {"type": "password"}):
                        login_form = f
                        break
                if not login_form and forms:
                    login_form = forms[0]

                if login_form:
                    user_field = pass_field = None
                    for inp in login_form.find_all("input"):
                        name = (inp.get("name") or "").strip()
                        tp = (inp.get("type") or "text").lower()
                        if not name:
                            continue
                        if tp == "password":
                            pass_field = name
                        elif any(kw in name.lower() for kw in ("user", "email", "login", "account", "name")):
                            user_field = user_field or name
                    action = login_form.get("action") or ""
                    method = (login_form.get("method") or "POST").upper()
                    form_url = urljoin(login_url, action) if action else login_url
                    self.form_detect_label.configure(
                        text=f"Found: {method} {form_url}",
                        foreground=CLR["success"]
                    )
                    bits = []
                    if user_field:
                        bits.append(f"user='{user_field}'")
                    if pass_field:
                        bits.append(f"pass='{pass_field}'")
                    self.form_summary_label.configure(
                        text="Form: " + ", ".join(bits) + (" — ready!" if user_field and pass_field else ""),
                        foreground=CLR["success"] if user_field and pass_field else CLR["warning"]
                    )
                else:
                    self.form_detect_label.configure(
                        text=f"No form found at {login_url}",
                        foreground=CLR["warning"]
                    )
                    self.form_summary_label.configure(
                        text="Try: /rest/user/login, /api/auth/login, or /login",
                        foreground=CLR["info"]
                    )
            else:
                self.form_detect_label.configure(
                    text=f"Unknown type at {login_url}",
                    foreground=CLR["warning"]
                )

        except requests.RequestException as e:
            self.form_detect_label.configure(
                text=f"Connection failed: {e}", foreground=CLR["danger"]
            )
        except Exception as e:
            self.form_detect_label.configure(
                text=f"Error: {e}", foreground=CLR["danger"]
            )
        finally:
            self.form_detect_btn.configure(state=NORMAL, text="Auto-Detect")

    # =========================== TAB: SCANS =================================
    def _build_tab_scans(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=1)

        card = _make_card(parent, "OWASP API Security Top 10 (2023) - Select Scans")
        card.pack(fill="both", expand=True, padx=10, pady=(10, 6))
        inner = card.content
        inner.columnconfigure(0, weight=1)

        # Info text
        ttk.Label(inner, text="Choose which API security categories to audit during the scan.",
                  style="Muted.TLabel").grid(row=0, column=0, sticky=W, padx=14, pady=(6, 4))

        # Checkboxes in a scrollable frame
        scan_canvas = Canvas(inner, bg=CLR["bg_card"], highlightthickness=0, height=260)
        scan_canvas.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)

        scan_inner = ttk.Frame(scan_canvas, style="Card.TFrame")
        scan_canvas.create_window((0, 0), window=scan_inner, anchor="nw")

        columns = 2
        for i, (label, key, default) in enumerate(API_CHECKS):
            var = BooleanVar(value=default)
            self.api_vars[key] = var
            col = i % columns
            row = i // columns
            cb = ttk.Checkbutton(scan_inner, text=label, variable=var,
                                 style="Card.TCheckbutton")
            cb.grid(row=row, column=col, sticky=W, padx=14, pady=4)

        scan_inner.update_idletasks()
        scan_canvas.configure(scrollregion=scan_canvas.bbox("all"))

        # Toggle buttons
        btn_frame = ttk.Frame(inner, style="Card.TFrame")
        btn_frame.grid(row=2, column=0, sticky="ew", padx=14, pady=(8, 10))

        ttk.Button(btn_frame, text="Select All", style="Small.TButton",
                   command=lambda: self._toggle_all_scans(True)).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Deselect All", style="Small.TButton",
                   command=lambda: self._toggle_all_scans(False)).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Toggle API 1-10", style="Small.TButton",
                   command=self._toggle_api1_10).pack(side="left", padx=2)

    # =========================== TAB: ADVANCED ==============================
    def _build_tab_advanced(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=1)

        # --- Card: Performance ---
        card1 = _make_card(parent, "Performance & Network")
        card1.pack(fill="x", padx=10, pady=(10, 6))
        inner = card1.content
        inner.columnconfigure(0, weight=1)

        perf_frame = ttk.Frame(inner, style="Card.TFrame")
        perf_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=6)

        ttk.Label(perf_frame, text="Threads", style="Card.TLabel").pack(side="left")
        ttk.Entry(perf_frame, textvariable=self.threads_var, width=6,
                  font=FONTS["body"]).pack(side="left", padx=(6, 0))
        ttk.Label(perf_frame, text="(concurrent workers)",
                  style="Muted.TLabel").pack(side="left", padx=(4, 20))

        ttk.Label(perf_frame, text="Timeout", style="Card.TLabel").pack(side="left")
        ttk.Entry(perf_frame, textvariable=self.timeout_var, width=6,
                  font=FONTS["body"]).pack(side="left", padx=(6, 0))
        ttk.Label(perf_frame, text="sec  (0 < t <= 600)",
                  style="Muted.TLabel").pack(side="left", padx=(4, 0))

        proxy_frame = ttk.Frame(inner, style="Card.TFrame")
        proxy_frame.grid(row=1, column=0, sticky="ew", padx=14, pady=4)
        ttk.Label(proxy_frame, text="Proxy", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(proxy_frame, textvariable=self.proxy_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Label(proxy_frame, text="http://127.0.0.1:8080",
                  style="Muted.TLabel").pack(side="left", padx=(6, 0))

        ttk.Separator(inner, orient=HORIZONTAL).grid(
            row=2, column=0, sticky="ew", padx=14, pady=6)

        # --- Card: Flags ---
        card2 = _make_card(parent, "Scanner Options")
        card2.pack(fill="x", padx=10, pady=6)
        inner2 = card2.content

        ttk.Checkbutton(inner2, text="Disable TLS certificate validation (--insecure) - DANGEROUS, testing only",
                        variable=self.insecure_var,
                        style="Card.TCheckbutton").pack(anchor=W, padx=14, pady=3)
        ttk.Checkbutton(inner2, text="Debug mode - verbose logging to console",
                        variable=self.debug_var,
                        style="Card.TCheckbutton").pack(anchor=W, padx=14, pady=3)
        ttk.Checkbutton(inner2, text="Dummy mode - use fake data for request bodies",
                        variable=self.dummy_var,
                        style="Card.TCheckbutton").pack(anchor=W, padx=14, pady=3)
        ttk.Checkbutton(inner2, text="API3 active mass-assignment tests (--api3-active)",
                        variable=self.api3_active_var,
                        style="Card.TCheckbutton").pack(anchor=W, padx=14, pady=3)
        ttk.Checkbutton(inner2, text="Chain Mode  auto-escalate BOLA leaks into other endpoints (--chain-mode)",
                        variable=self.chain_mode_var,
                        style="Card.TCheckbutton").pack(anchor=W, padx=14, pady=3)

        chain_depth_frame = ttk.Frame(inner2, style="Card.TFrame")
        chain_depth_frame.pack(anchor=W, padx=14, pady=(0, 4))
        ttk.Label(chain_depth_frame, text="Chain Depth", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(chain_depth_frame, textvariable=self.chain_depth_var, width=4,
                  font=FONTS["body"]).pack(side="left")
        ttk.Label(chain_depth_frame, text="(1-3, recursive escalation depth)",
                  style="Muted.TLabel").pack(side="left", padx=(6, 0))

        # --- Card: Plan / Verify ---
        card_plan = _make_card(parent, "Plan & Verification")
        card_plan.pack(fill="x", padx=10, pady=6)
        inner_plan = card_plan.content
        inner_plan.columnconfigure(0, weight=1)

        ttk.Checkbutton(inner_plan, text="Plan then scan (--plan-then-scan)",
                        variable=self.plan_then_scan_var,
                        style="Card.TCheckbutton").grid(row=0, column=0, sticky=W, padx=14, pady=3)
        ttk.Checkbutton(inner_plan, text="Verify plan - probe each planned request (--verify-plan)",
                        variable=self.verify_plan_var,
                        style="Card.TCheckbutton").grid(row=1, column=0, sticky=W, padx=14, pady=3)

        sc_frame = ttk.Frame(inner_plan, style="Card.TFrame")
        sc_frame.grid(row=2, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(sc_frame, text="Success Codes", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(sc_frame, textvariable=self.success_codes_var, width=18,
                  font=FONTS["body"]).pack(side="left")
        ttk.Label(sc_frame, text="200-299,302", style="Muted.TLabel").pack(side="left", padx=(6, 0))

        ttk.Checkbutton(inner_plan, text="Normalize version segments  /v2.0/ (--normalize-version)",
                        variable=self.normalize_version_var,
                        style="Card.TCheckbutton").grid(row=3, column=0, sticky=W, padx=14, pady=3)

        # --- Card: Resilience ---
        card_retry = _make_card(parent, "Resilience & Retry")
        card_retry.pack(fill="x", padx=10, pady=6)
        inner_retry = card_retry.content

        retry_frame = ttk.Frame(inner_retry, style="Card.TFrame")
        retry_frame.pack(anchor=W, padx=14, pady=3)
        ttk.Label(retry_frame, text="5xx Retries", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(retry_frame, textvariable=self.retry500_var, width=6,
                  font=FONTS["body"]).pack(side="left")
        ttk.Label(retry_frame, text="(default 1)", style="Muted.TLabel").pack(side="left", padx=(6, 12))
        ttk.Checkbutton(retry_frame, text="Disable 5xx retries (--no-retry-500)",
                        variable=self.no_retry_500_var,
                        style="Card.TCheckbutton").pack(side="left")

        # --- Card: URL Rewriting ---
        card_rewrite = _make_card(parent, "URL Rewrite & Sanitize")
        card_rewrite.pack(fill="x", padx=10, pady=6)
        inner_rw = card_rewrite.content
        inner_rw.columnconfigure(0, weight=1)

        rw_frame = ttk.Frame(inner_rw, style="Card.TFrame")
        rw_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(rw_frame, text="Rewrite Rules", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(rw_frame, textvariable=self.rewrite_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Label(rw_frame, text="regex=>replacement", style="Muted.TLabel").pack(side="left", padx=(6, 0))

        ttk.Checkbutton(inner_rw, text="Disable built-in URL normalization (--no-sanitize)",
                        variable=self.no_sanitize_var,
                        style="Card.TCheckbutton").grid(row=1, column=0, sticky=W, padx=14, pady=3)

        # --- Card: Export & Database ---
        card_export = _make_card(parent, "Export & Database")
        card_export.pack(fill="x", padx=10, pady=6)
        inner_exp = card_export.content
        inner_exp.columnconfigure(0, weight=1)

        exp_frame = ttk.Frame(inner_exp, style="Card.TFrame")
        exp_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(exp_frame, text="Export Vars", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(exp_frame, textvariable=self.export_vars_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Label(exp_frame, text=".yml / .yaml / .json", style="Muted.TLabel").pack(side="left", padx=(6, 0))
        ttk.Button(exp_frame, text="...", width=3, style="Small.TButton",
                   command=lambda: self._browse_save("export_vars_var", "*.yml *.yaml *.json")
                   ).pack(side="left", padx=(4, 0))

        db_frame = ttk.Frame(inner_exp, style="Card.TFrame")
        db_frame.grid(row=1, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(db_frame, text="DB Path", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(db_frame, textvariable=self.db_path_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Label(db_frame, text="SQLite cache file", style="Muted.TLabel").pack(side="left", padx=(6, 0))
        ttk.Button(db_frame, text="...", width=3, style="Small.TButton",
                   command=lambda: self._browse_save("db_path_var", "*.db")
                   ).pack(side="left", padx=(4, 0))

        # --- Card: API10 Safe Consumption Tuning ---
        card_sc = _make_card(parent, "API10  Safe Consumption Scan Tuning")
        card_sc.pack(fill="x", padx=10, pady=6)
        inner_sc = card_sc.content
        inner_sc.columnconfigure(0, weight=1)

        ttk.Checkbutton(inner_sc, text="Deep Scan  thorough API10 testing (APISCAN_DEEP_SCAN)",
                        variable=self.deep_scan_var,
                        style="Card.TCheckbutton").grid(row=0, column=0, sticky=W, padx=14, pady=3)
        ttk.Checkbutton(inner_sc, text="Fast Mode  skip expensive tests (APISCAN_FAST, default on)",
                        variable=self.fast_mode_var,
                        style="Card.TCheckbutton").grid(row=1, column=0, sticky=W, padx=14, pady=3)

        int_frame = ttk.Frame(inner_sc, style="Card.TFrame")
        int_frame.grid(row=2, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(int_frame, text="Intensity", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        int_menu = ttk.Combobox(int_frame, textvariable=self.intensity_var,
                                values=["low", "medium", "high"], state="readonly",
                                width=10, font=FONTS["body"])
        int_menu.pack(side="left")
        ttk.Label(int_frame, text="APISCAN_INTENSITY", style="Muted.TLabel").pack(side="left", padx=(8, 0))

        # --- Card: Certificates ---
        card3 = _make_card(parent, "Client Certificates (mTLS)")
        card3.pack(fill="x", padx=10, pady=6)
        inner3 = card3.content
        inner3.columnconfigure(0, weight=1)

        cert1 = ttk.Frame(inner3, style="Card.TFrame")
        cert1.grid(row=0, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(cert1, text="Client Cert", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(cert1, textvariable=self.client_cert_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Button(cert1, text="...", width=3, style="Small.TButton",
                   command=lambda: self._browse_file("client_cert_var", "*.pem *.crt")
                   ).pack(side="left", padx=(4, 0))

        cert2 = ttk.Frame(inner3, style="Card.TFrame")
        cert2.grid(row=1, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(cert2, text="Client Key", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(cert2, textvariable=self.client_key_var,
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Button(cert2, text="...", width=3, style="Small.TButton",
                   command=lambda: self._browse_file("client_key_var", "*.pem *.key")
                   ).pack(side="left", padx=(4, 0))

        cert3 = ttk.Frame(inner3, style="Card.TFrame")
        cert3.grid(row=2, column=0, sticky="ew", padx=14, pady=3)
        ttk.Label(cert3, text="Cert Password", style="Card.TLabel",
                  width=16, anchor=E).pack(side="left", padx=(0, 8))
        ttk.Entry(cert3, textvariable=self.cert_password_var, show="*",
                  font=FONTS["body"]).pack(side="left", fill="x", expand=True)
        ttk.Label(cert3, text="(if key encrypted)", style="Muted.TLabel").pack(side="left", padx=(6, 0))

    # =========================== OUTPUT PANEL ===============================
    def _build_output_panel(self, parent: ttk.Frame):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=0)   # header  no stretch
        parent.rowconfigure(1, weight=0)   # banner  toggled via _show/_hide
        parent.rowconfigure(2, weight=1)   # output   expand fully

        # Output header
        out_header = ttk.Frame(parent, style="Header.TFrame")
        out_header.grid(row=0, column=0, sticky="ew")
        ttk.Label(out_header, text="  Scan Output",
                  font=("Segoe UI", 10, "bold"),
                  foreground=CLR["text_primary"],
                  background=CLR["bg_header"]).pack(side="left", padx=8, pady=3)

        self.output_status = ttk.Label(out_header, text="",
                                        font=FONTS["small"],
                                        foreground=CLR["text_muted"],
                                        background=CLR["bg_header"])
        self.output_status.pack(side="right", padx=12)

        # Dark terminal-style output with proper scrolling
        self.output_text = ScrolledText(
            parent, wrap="word", state=DISABLED,
            font=FONTS["mono"],
            background=CLR["bg_output"],
            foreground=CLR["text_primary"],
            insertbackground=CLR["text_primary"],
            insertwidth=2,
            selectbackground=CLR["accent_dark"],
            selectforeground="#ffffff",
            borderwidth=0,
            highlightthickness=0,
            padx=8, pady=6,
            relief="flat"
        )
        self.output_text.grid(row=2, column=0, sticky="nsew")

        # --- Banner image (shown on startup, hidden when scan starts) ---
        self._banner_label = ttk.Label(parent, background=CLR["bg_output"], anchor="center")
        self._banner_label.grid(row=1, column=0, sticky="nsew")
        self._load_banner_image()
        # Style the scrollbar wider for better usability
        self.output_text.vbar.configure(width=12)
        # Bind mousewheel for smooth scrolling on all platforms
        self.output_text.bind("<MouseWheel>", lambda e: self._on_mousewheel(e))
        self.output_text.bind("<Shift-MouseWheel>", lambda e: self._on_mousewheel_h(e))
        # macOS scrolling
        self.output_text.bind("<Button-4>", lambda e: self.output_text.yview_scroll(-3, "units"))
        self.output_text.bind("<Button-5>", lambda e: self.output_text.yview_scroll(3, "units"))

        # Configure syntax-highlighting tags
        tags = {
            "red":     CLR["danger"],
            "green":   CLR["success"],
            "yellow":  CLR["warning"],
            "cyan":    CLR["cyan"],
            "magenta": CLR["purple"],
            "white":   CLR["text_primary"],
            "info":    CLR["text_secondary"],
            "warn":    CLR["orange"],
            "fail":    CLR["danger"],
            "ok":      CLR["success"],
            "done":    CLR["success"],
            "header":  CLR["accent"],
        }
        for name, color in tags.items():
            self.output_text.tag_configure(name, foreground=color)
        self.output_text.tag_configure("bold", font=("Cascadia Code", 9, "bold"))
        self.output_text.tag_configure("header", font=("Cascadia Code", 10, "bold"),
                                        foreground=CLR["accent"])

    def _load_banner_image(self):
        self._banner_img = None
        img_path = Path(__file__).parent / BANNER_FILE
        if not img_path.is_file():
            return

        try:
            if Image is not None and ImageTk is not None:
                with Image.open(img_path) as img:
                    img = img.convert("RGBA")
                    img.thumbnail(
                        (BANNER_DISPLAY_WIDTH, BANNER_DISPLAY_HEIGHT),
                        Image.Resampling.LANCZOS
                    )

                    # Keep the banner area exactly 15:5 and center the image.
                    canvas = Image.new(
                        "RGBA",
                        (BANNER_DISPLAY_WIDTH, BANNER_DISPLAY_HEIGHT),
                        CLR["bg_output"]
                    )
                    x = (BANNER_DISPLAY_WIDTH - img.width) // 2
                    y = (BANNER_DISPLAY_HEIGHT - img.height) // 2
                    canvas.alpha_composite(img, (x, y))

                self._banner_img = ImageTk.PhotoImage(canvas)
            else:
                # Fallback when Pillow is not installed.
                # This displays the image as-is, so use a 900x300 apiscan.png.
                self._banner_img = PhotoImage(file=str(img_path))

            self._banner_label.configure(image=self._banner_img, compound="center")
        except Exception as exc:
            self._banner_img = None
            self.text_queue.put(f"[WARN] Could not load banner image: {exc}")

    # =========================================================================
    # HELPERS
    # =========================================================================
    def _on_mousewheel(self, event):
        self.output_text.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_mousewheel_h(self, event):
        self.output_text.xview_scroll(int(-1 * (event.delta / 120)), "units")

    def _browse_swagger(self):
        path = filedialog.askopenfilename(
            title="Select Swagger/OpenAPI file",
            filetypes=[("Swagger files", "*.json *.yaml *.yml"), ("All files", "*.*")]
        )
        if path:
            self.swagger_var.set(path)

    def _browse_file(self, var_name: str, filetypes_str: str):
        path = filedialog.askopenfilename(
            title=f"Select {var_name.replace('_', ' ')}",
            filetypes=[(filetypes_str, filetypes_str), ("All files", "*.*")]
        )
        if path:
            getattr(self, var_name).set(path)

    def _browse_save(self, var_name: str, filetypes_str: str):
        path = filedialog.asksaveasfilename(
            title=f"Save {var_name.replace('_', ' ')}",
            filetypes=[(filetypes_str, filetypes_str), ("All files", "*.*")]
        )
        if path:
            getattr(self, var_name).set(path)

    def _toggle_show(self, entry: ttk.Entry):
        entry.configure(show="" if entry.cget("show") == "*" else "*")

    def _toggle_all_scans(self, state: bool):
        for key, var in self.api_vars.items():
            if key != "api11":
                var.set(state)

    def _toggle_api1_10(self):
        current_all = all(var.get() for key, var in self.api_vars.items() if key != "api11")
        new_state = not current_all
        for key, var in self.api_vars.items():
            if key != "api11":
                var.set(new_state)

    def _clear_output(self):
        self.output_text.configure(state=NORMAL)
        self.output_text.delete("1.0", END)
        self.output_text.configure(state=DISABLED)

    def _show_banner(self):
        if getattr(self, "_banner_img", None):
            self._output_frame.rowconfigure(1, weight=0, minsize=BANNER_DISPLAY_HEIGHT)
            self._banner_label.grid()

    def _hide_banner(self):
        self._banner_label.grid_remove()
        self._output_frame.rowconfigure(1, weight=0, minsize=0)

    def _open_output_folder(self):
        try:
            base = Path.cwd()
            date_dirs = sorted(base.glob("apiscan_*"), key=os.path.getmtime, reverse=True)
            target = date_dirs[0] if date_dirs else base
        except Exception:
            target = Path.cwd()
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(target))
            elif sys.platform.startswith("darwin"):
                subprocess.Popen(["open", str(target)])
            else:
                subprocess.Popen(["xdg-open", str(target)])
        except Exception as e:
            self._log(f"Could not open folder: {e}", "fail")

    def _log(self, message: str, tag: str = "white"):
        self.output_text.configure(state=NORMAL)
        at_bottom = self.output_text.yview()[1] >= 0.99
        self.output_text.insert(END, message + ("\n" if not message.endswith("\n") else ""), tag)
        if at_bottom:
            self.output_text.see(END)
        self.output_text.configure(state=DISABLED)

    def _update_header_status(self, text: str, color: str = CLR["text_muted"]):
        self.header_status.configure(text=text, foreground=color)

    def _update_status(self, text: str):
        self.status_text.configure(text=text)

    def _poll_queue(self):
        try:
            while True:
                text = self.text_queue.get_nowait()
                # Strip ANSI escape sequences (colorama leftovers)
                text = _re_ansi.sub("", text)
                line = text.rstrip("\n\r")
                if not line.strip():
                    continue

                tag = "white"
                upper = line.upper()
                if any(p in upper for p in ["[OK]", "[+]", "COMPLETE", "SUCCESS"]):
                    tag = "green"
                elif any(p in upper for p in ["[FAIL]", "[-]", "ERROR", "FAILED",
                                               "EXCEPTION", "TRACEBACK"]):
                    tag = "red"
                elif any(p in upper for p in ["[WARN]", "[WARNING]", "[!]"]):
                    tag = "yellow"
                elif any(p in upper for p in ["[*]", "[INFO]", "[DEBUG]"]):
                    tag = "info"
                elif "VULNERABILITIES FOUND" in upper:
                    tag = "red" if "0" not in line else "green"
                elif "PROXY" in upper:
                    tag = "magenta"
                elif line.startswith("=") or line.startswith("==="):
                    tag = "header"

                self._log(line + "\n", tag)
        except queue.Empty:
            pass

        if self.running and self.scan_thread and not self.scan_thread.is_alive():
            self._on_scan_complete()

        self.root.after(100, self._poll_queue)

    # =========================================================================
    # SCAN EXECUTION
    # =========================================================================
    def _build_args(self) -> list[str]:
        args = ["--url", self.url_var.get().strip()]

        swagger = self.swagger_var.get().strip()
        if swagger:
            args.extend(["--swagger", swagger])

        if self.crawl_var.get():
            args.append("--crawl")
            try:
                depth = int(self.crawl_depth_var.get())
                args.extend(["--crawl-depth", str(depth)])
            except ValueError:
                pass
            if self.crawl_aggressive_var.get():
                args.append("--crawl-aggressive")
            if self.crawl_passive_var.get():
                args.append("--crawl-passive")
            if not self.crawl_validate_var.get():
                args.append("--no-crawl-validate")
            else:
                val_mode = self.crawl_validate_mode_var.get().strip()
                if val_mode in ("balanced", "strict"):
                    args.extend(["--crawl-validate-mode", val_mode])
                try:
                    val_w = int(self.crawl_validate_workers_var.get())
                    if val_w > 0:
                        args.extend(["--crawl-validate-workers", str(val_w)])
                except ValueError:
                    pass

        for name, var in [("threads", self.threads_var), ("timeout", self.timeout_var)]:
            try:
                val = int(var.get()) if name == "threads" else float(var.get())
                if val > 0:
                    args.extend([f"--{name}", str(val)])
            except ValueError:
                pass

        proxy = self.proxy_var.get().strip()
        if proxy:
            args.extend(["--proxy", proxy])

        for flag, var in [
            ("--insecure", self.insecure_var),
            ("--debug", self.debug_var),
            ("--dummy", self.dummy_var),
            ("--plan-only", self.plan_only_var),
            ("--plan-then-scan", self.plan_then_scan_var),
            ("--verify-plan", self.verify_plan_var),
            ("--no-sanitize", self.no_sanitize_var),
            ("--api3-active", self.api3_active_var),
            ("--chain-mode", self.chain_mode_var),
        ]:
            if var.get():
                args.append(flag)

        # Chain depth (only when chain-mode is active)
        if self.chain_mode_var.get():
            try:
                cd = int(self.chain_depth_var.get())
                if cd > 1:
                    args.extend(["--chain-depth", str(min(cd, 3))])
            except ValueError:
                pass

        # Success codes (only if non-default)
        sc = self.success_codes_var.get().strip()
        if sc and sc != "200-299":
            args.extend(["--success-codes", sc])

        # Retry logic
        if self.no_retry_500_var.get():
            args.append("--no-retry-500")
        else:
            try:
                r5 = int(self.retry500_var.get())
                if r5 != 1:
                    args.extend(["--retry500", str(r5)])
            except ValueError:
                pass

        # Version normalization
        if self.normalize_version_var.get():
            args.append("--normalize-version")
        if self.no_normalize_version_var.get():
            args.append("--no-normalize-version")

        # Export vars
        ev = self.export_vars_var.get().strip()
        if ev:
            args.extend(["--export_vars", ev])

        # DB path
        db = self.db_path_var.get().strip()
        if db:
            args.extend(["--db-path", db])

        # URL rewrites (support multiple rules separated by ;; )
        rw = self.rewrite_var.get().strip()
        if rw:
            for rule in rw.split(";;"):
                rule = rule.strip()
                if rule:
                    args.extend(["--rewrite", rule])

        flow = self.flow_var.get().strip()
        if flow and flow != "none":
            args.extend(["--flow", flow])
            if flow == "token":
                token = self.token_var.get().strip()
                if token:
                    args.extend(["--token", token])
            elif flow == "basic":
                basic = self.basic_auth_var.get().strip()
                if basic:
                    args.extend(["--basic-auth", basic])
            elif flow == "ntlm":
                ntlm = self.ntlm_var.get().strip()
                if ntlm:
                    args.extend(["--ntlm", ntlm])
            elif flow == "form":
                login_url = self.form_login_url_var.get().strip()
                username = self.form_login_user_var.get().strip()
                password = self.form_login_pass_var.get().strip()
                token_path = self.form_login_token_path_var.get().strip()
                if username:
                    args.extend(["--login-username", username])
                if password:
                    args.extend(["--login-password", password])
                if login_url:
                    args.extend(["--login-url", login_url])
                if token_path:
                    args.extend(["--token-path", token_path])

        apikey = self.apikey_var.get().strip()
        if apikey:
            args.extend(["--apikey", apikey])
            header = self.apikey_header_var.get().strip()
            if header:
                args.extend(["--apikey-header", header])

        for key, var in [
            ("--client-id", self.client_id_var),
            ("--client-secret", self.client_secret_var),
            ("--token-url", self.token_url_var),
            ("--auth-url", self.auth_url_var),
            ("--redirect-uri", self.redirect_uri_var),
            ("--scope", self.scope_var),
        ]:
            val = var.get().strip()
            if val:
                args.extend([key, val])

        for key, var in [
            ("--client-cert", self.client_cert_var),
            ("--client-key", self.client_key_var),
        ]:
            val = var.get().strip()
            if val:
                args.extend([key, val])
        cert_pwd = self.cert_password_var.get().strip()
        if cert_pwd:
            args.extend(["--cert-password", cert_pwd])

        for key, var in [
            ("--headers-file", self.headers_file_var),
            ("--ids-file", self.ids_file_var),
        ]:
            val = var.get().strip()
            if val:
                args.extend([key, val])

        for key, var in self.api_vars.items():
            if var.get():
                num = key.replace("api", "")
                args.append(f"--api{num}")

        return args

    def _start_scan(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Validation Error", "Target URL is required.")
            return

        if not self.swagger_var.get().strip() and not self.crawl_var.get():
            if not messagebox.askyesno(
                "No Specification",
                "No Swagger file specified and crawling is not enabled.\n"
                "The scan requires a specification file (or --crawl).\n\n"
                "Continue anyway?"
            ):
                return

        if not any(var.get() for var in self.api_vars.values()):
            messagebox.showwarning("No Scans", "No OWASP API scans selected. Nothing to scan.")
            return

        self.running = True
        self._hide_banner()  # remove startup image
        self.scan_btn.configure(state=DISABLED)
        self.stop_btn.configure(state=NORMAL)
        self.header_scan_btn.configure(state=DISABLED)
        self.header_stop_btn.configure(state=NORMAL)
        self._clear_output()
        self.progress_bar.start(10)
        self._update_header_status("Scanning...", CLR["warning"])
        self._update_status("Scan in progress - please wait...")

        args_list = self._build_args()
        cmd = [sys.executable, "apiscan.py"] + args_list

        self._log("=" * 62, "header")
        self._log(f"  APISCAN v{__version__} - Security Scan Started", "header")
        self._log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "header")
        self._log("=" * 62, "header")
        self._log(f"Command: {' '.join(cmd)}", "info")
        self._log("")

        self.scan_thread = threading.Thread(
            target=self._run_scan_process, args=(cmd,), daemon=True
        )
        self.scan_thread.start()

    def _run_scan_process(self, cmd: list[str]):
        try:
            env = os.environ.copy()
            # Force UTF-8 to avoid cp1252 UnicodeEncodeError in banner/colorama
            env["PYTHONUTF8"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"
            # Force unbuffered stdout so the GUI sees output in real-time
            # instead of waiting for 8KB buffers to fill (block-buffered pipe default).
            env["PYTHONUNBUFFERED"] = "1"
            # Disable tqdm dynamic progress bars: they use \\r (carriage return)
            # without \\n, which blocks line-based pipe readers.  The built-in
            # ProgressBar fallback handles progress display for the GUI instead.
            env["TQDM_DISABLE"] = "1"
            # Disable colorama's Windows console wrapping (it crashes on pipes)
            env["CLICOLOR"] = "0"
            env["NO_COLOR"] = "1"
            # API10 Safe Consumption tuning
            env["APISCAN_DEEP_SCAN"] = "1" if self.deep_scan_var.get() else "0"
            env["APISCAN_FAST"] = "1" if self.fast_mode_var.get() else "0"
            env["APISCAN_INTENSITY"] = self.intensity_var.get().strip() or "medium"
            # Use binary pipe + manual UTF-8 decode to completely bypass
            # colorama's cp1252 encoding issues in the child process
            self.scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                env=env,
                cwd=Path(__file__).parent
            )
            # TQDM is disabled in the subprocess (env TQDM_DISABLE=1) so all
            # output is line-buffered with proper \\n. Safe to use readline().
            for raw_line in iter(self.scan_process.stdout.readline, b""):
                if not self.running:
                    self.scan_process.terminate()
                    break
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    line = raw_line.decode("utf-8", errors="replace")
                # Split \\r segments (safety net for any remaining carriage-return
                # output like ProgressBar fallback on TTY).
                for segment in line.split("\r"):
                    stripped = segment.strip()
                    if stripped:
                        self.text_queue.put(stripped)
            self.scan_process.stdout.close()
            returncode = self.scan_process.wait()
            if returncode != 0 and self.running:
                self.text_queue.put(f"[!] APISCAN exited with code {returncode} (possibly a crash)")
        except Exception as e:
            self.text_queue.put(f"[ERROR] Scan process failed: {e}")
        finally:
            self.scan_process = None

    def _stop_scan(self):
        if self.scan_process and self.scan_process.poll() is None:
            self.text_queue.put("[!] Scan aborted by user.")
            self.scan_process.terminate()
        self.running = False
        self._on_scan_complete()

    def _on_scan_complete(self):
        self.running = False
        self.scan_thread = None
        self.scan_process = None
        self.root.after(0, self._finish_ui)

    def _finish_ui(self):
        self.progress_bar.stop()
        self.scan_btn.configure(state=NORMAL)
        self.stop_btn.configure(state=DISABLED)
        self.header_scan_btn.configure(state=NORMAL)
        self.header_stop_btn.configure(state=DISABLED)
        self._update_header_status("Ready", CLR["success"])
        self._update_status("Scan completed - reports available in output folder")

        self._log("")
        self._log("=" * 62, "header")
        self._log(f"  Scan Completed - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "header")
        self._log("=" * 62, "header")

        self.root.after(200, lambda: messagebox.showinfo(
            "Scan Complete",
            "APISCAN scan has finished.\n\nOpen the output folder to view the HTML reports."
        ))

    def _on_close(self):
        if self.running:
            if messagebox.askyesno("Scan Running",
                                   "A scan is currently in progress.\nStop and exit?"):
                self._stop_scan()
            else:
                return
        self.root.destroy()


# =============================================================================
# ENTRY POINT
# =============================================================================
def main():
    root = Tk()
    _init_styles(root)
    # Make cursor blink visible on dark theme
    root.option_add("*insertWidth", 2)
    app = APISCANApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
