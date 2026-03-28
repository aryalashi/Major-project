"""
gui.py
------
Professional SOC-grade dashboard for the Signature-Based NIDS.

Design: Industrial cybersecurity aesthetic.
  - Deep navy/charcoal base with cyan and amber accents
  - Monospaced data, sharp borders, high information density
  - Left sidebar: system status + per-rule counters
  - Main panel: alert table, packet log, evidence log
  - Top bar: stat cards with live counters
  - Persistent search bar above tabs
  - Status LED, timestamps, export controls

Inspired by: Splunk, Wireshark, enterprise SIEM dashboards
"""

import sys
import csv
import time
import queue
import threading
import logging
import os
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QGroupBox, QPlainTextEdit, QStatusBar,
    QTabWidget, QFrame, QLineEdit, QFileDialog, QMessageBox,
    QSizePolicy, QScrollArea, QSplitter
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QSize
from PyQt6.QtGui import QColor, QFont, QPalette, QFontDatabase

# ------------------------------------------------------------------ #
#  NEW FEATURE TABS — imported safely with fallback                   #
# ------------------------------------------------------------------ #
try:
    from gui_tabs import NetworkScannerTab, HotspotMonitorTab
    NEW_TABS_AVAILABLE = True
except ImportError:
    NEW_TABS_AVAILABLE = False
    class NetworkScannerTab:  # type: ignore
        """Fallback stub when gui_new_tabs.py is missing."""
        def __init__(self, *a, **kw): pass
        def set_scanner(self, *a): pass
    class HotspotMonitorTab:  # type: ignore
        """Fallback stub when gui_new_tabs.py is missing."""
        def __init__(self, *a, **kw): pass
        def set_monitor(self, *a): pass

# ------------------------------------------------------------------ #
#  ANALYSIS — Confusion Matrix & Session Report                       #
# ------------------------------------------------------------------ #
# Not available in this version
ANALYZER_AVAILABLE = False

class ConfusionMatrixAnalyzer:  # type: ignore
    """Stub - analyzer not available"""
    def __init__(self, *a, **kw): pass
    def add_detection(self, *a, **kw): pass
    def save_report(self, *a, **kw): return "logs/report.txt"

class AnalysisDialog:  # type: ignore
    """Stub - analyzer not available"""
    def __init__(self, *a, **kw): pass
    def exec(self): return 0

logger = logging.getLogger("GUI")

# ------------------------------------------------------------------ #
#  SIGNAL BRIDGE                                                       #
# ------------------------------------------------------------------ #
class SignalBridge(QObject):
    alert_received  = pyqtSignal(dict)
    packet_received = pyqtSignal(dict)
    status_update   = pyqtSignal(str)


# ------------------------------------------------------------------ #
#  COLOR PALETTE                                                       #
# ------------------------------------------------------------------ #
C = {
    "bg_deep":     "#080c14",   # deepest background
    "bg_panel":    "#0d1220",   # panel background
    "bg_card":     "#111827",   # card / groupbox background
    "bg_row_alt":  "#0f1520",   # alternating table row
    "bg_input":    "#0a0f1a",   # input fields
    "border":      "#1e2d45",   # default border
    "border_hi":   "#2a4060",   # highlighted border
    "cyan":        "#00c8e0",   # primary accent
    "cyan_dim":    "#0a6878",   # dimmed cyan
    "amber":       "#f0a500",   # warning / medium
    "green":       "#00e676",   # success / low
    "red":         "#f44336",   # critical / error
    "orange":      "#ff6d00",   # high severity
    "text_primary":"#dce8f5",   # main text
    "text_muted":  "#4a6080",   # muted/secondary text
    "text_dim":    "#2a3850",   # very dim text
    "header_bg":   "#0a1628",   # table header
    "select_bg":   "#0d2040",   # selection background
    "tab_active":  "#0d1e35",   # active tab
    "sidebar":     "#0a0f1c",   # sidebar background
}

# Light theme palette
C_LIGHT = {
    "bg_deep":     "#f0f2f5",
    "bg_panel":    "#ffffff",
    "bg_card":     "#f7f9fc",
    "bg_row_alt":  "#f2f5f8",
    "bg_input":    "#ffffff",
    "border":      "#d0d8e4",
    "border_hi":   "#a0b4cc",
    "cyan":        "#0077aa",
    "cyan_dim":    "#b0d4e8",
    "amber":       "#c47800",
    "green":       "#1a8a3a",
    "red":         "#cc2200",
    "orange":      "#c45000",
    "text_primary":"#1a2a3a",
    "text_muted":  "#6a7f96",
    "text_dim":    "#b0c0d0",
    "header_bg":   "#e4eaf2",
    "select_bg":   "#d0e8f8",
    "tab_active":  "#eaf4fb",
    "sidebar":     "#e8ecf2",
}


def _build_style(c: dict) -> str:
    return (
        f"QMainWindow, QDialog {{"
        f"background-color: {c['bg_deep']};"
        f"color: {c['text_primary']};"
        f"font-family: 'Consolas', 'Courier New', monospace;"
        f"font-size: 14px;}}"

        f"QWidget {{background-color: transparent;"
        f"color: {c['text_primary']};"
        f"font-family: 'Consolas', 'Courier New', monospace;"
        f"font-size: 14px;}}"

        f"QFrame#sidebar {{background-color: {c['sidebar']};"
        f"border-right: 1px solid {c['border']};}}"

        f"QFrame#topbar {{background-color: {c['bg_panel']};"
        f"border-bottom: 1px solid {c['border']};}}"

        f"QFrame#statCard {{background-color: {c['bg_card']};"
        f"border: 1px solid {c['border']}; border-radius: 4px; padding: 6px;}}"

        f"QFrame#headerBar {{background-color: {c['bg_deep']};"
        f"border-bottom: 2px solid {c['cyan_dim']};}}"

        f"QGroupBox {{background-color: {c['bg_panel']};"
        f"border: 1px solid {c['border']}; border-radius: 3px;"
        f"margin-top: 14px; padding-top: 8px;"
        f"font-family: 'Consolas', monospace; font-size: 12px;"
        f"font-weight: bold; color: {c['cyan']};"
        f"letter-spacing: 1px; text-transform: uppercase;}}"

        f"QGroupBox::title {{subcontrol-origin: margin; left: 8px;"
        f"padding: 0 6px; background-color: {c['bg_panel']};"
        f"color: {c['cyan']}; letter-spacing: 2px;}}"

        f"QPushButton {{background-color: transparent;"
        f"color: {c['cyan']}; border: 1px solid {c['cyan_dim']};"
        f"border-radius: 2px; padding: 6px 16px;"
        f"font-family: 'Consolas', monospace; font-size: 13px;"
        f"font-weight: bold; letter-spacing: 1px; min-width: 80px;}}"

        f"QPushButton:hover {{background-color: {c['cyan_dim']};"
        f"border-color: {c['cyan']}; color: {c['bg_deep']};}}"

        f"QPushButton:pressed {{background-color: {c['cyan']}; color: {c['bg_deep']};}}"
        f"QPushButton:disabled {{color: {c['text_dim']}; border-color: {c['text_dim']};}}"

        f"QPushButton#startBtn {{color: {c['green']}; border-color: {c['green']};}}"
        f"QPushButton#startBtn:hover {{background-color: {c['green']}; color: {c['bg_deep']};}}"
        f"QPushButton#stopBtn {{color: {c['red']}; border-color: {c['red']};}}"
        f"QPushButton#stopBtn:hover {{background-color: {c['red']}; color: #fff;}}"
        f"QPushButton#exportBtn {{color: {c['amber']}; border-color: {c['amber']};}}"
        f"QPushButton#exportBtn:hover {{background-color: {c['amber']}; color: {c['bg_deep']};}}"

        f"QPushButton#clearBtn {{color: {c['text_muted']}; border-color: {c['text_dim']};"
        f"font-size: 12px; padding: 5px 12px; min-width: 50px;}}"
        f"QPushButton#clearBtn:hover {{background-color: {c['border']}; color: {c['text_primary']};}}"

        f"QPushButton#themeBtn {{color: {c['text_muted']}; border-color: {c['border']};"
        f"font-size: 14px; padding: 3px 8px; min-width: 36px;}}"
        f"QPushButton#themeBtn:hover {{background-color: {c['border']}; color: {c['text_primary']};}}"

        f"QComboBox {{background-color: {c['bg_input']}; color: {c['text_primary']};"
        f"border: 1px solid {c['border']}; border-radius: 2px; padding: 4px 8px;"
        f"font-family: 'Consolas', monospace; font-size: 13px; min-width: 120px;}}"
        f"QComboBox:focus {{border-color: {c['cyan_dim']};}}"
        f"QComboBox::drop-down {{border: none; width: 20px;}}"
        f"QComboBox QAbstractItemView {{background-color: {c['bg_card']};"
        f"color: {c['text_primary']}; border: 1px solid {c['border_hi']};"
        f"selection-background-color: {c['select_bg']};}}"

        f"QLineEdit {{background-color: {c['bg_input']}; color: {c['cyan']};"
        f"border: 1px solid {c['border']}; border-radius: 2px; padding: 5px 10px;"
        f"font-family: 'Consolas', monospace; font-size: 14px;}}"
        f"QLineEdit:focus {{border-color: {c['cyan']};}}"

        f"QTableWidget {{background-color: {c['bg_panel']}; color: {c['text_primary']};"
        f"gridline-color: {c['border']}; border: none;"
        f"font-family: 'Consolas', monospace; font-size: 13px;}}"
        f"QTableWidget::item {{padding: 3px 6px; border: none;}}"
        f"QTableWidget::item:alternate {{background-color: {c['bg_row_alt']};}}"
        f"QTableWidget::item:selected {{background-color: {c['select_bg']}; color: {c['cyan']};}}"

        f"QHeaderView::section {{background-color: {c['header_bg']}; color: {c['cyan']};"
        f"padding: 6px 8px; border: none;"
        f"border-right: 1px solid {c['border']};"
        f"border-bottom: 1px solid {c['cyan_dim']};"
        f"font-family: 'Consolas', monospace; font-size: 12px;"
        f"font-weight: bold; letter-spacing: 1px; text-transform: uppercase;}}"
        f"QHeaderView::section:last {{border-right: none;}}"

        f"QPlainTextEdit {{background-color: {c['bg_deep']}; color: {c['green']};"
        f"border: none; border-left: 2px solid {c['border']};"
        f"font-family: 'Consolas', 'Courier New', monospace; font-size: 13px;}}"

        f"QTabWidget::pane {{background-color: {c['bg_panel']};"
        f"border: 1px solid {c['border']}; border-top: none;}}"
        f"QTabBar {{background-color: {c['bg_deep']};}}"
        f"QTabBar::tab {{background-color: {c['bg_deep']}; color: {c['text_muted']};"
        f"padding: 7px 20px; border: 1px solid {c['border']}; border-bottom: none;"
        f"font-family: 'Consolas', monospace; font-size: 13px;"
        f"font-weight: bold; letter-spacing: 1px; margin-right: 2px; min-width: 80px;}}"
        f"QTabBar::tab:selected {{background-color: {c['tab_active']}; color: {c['cyan']};"
        f"border-color: {c['border_hi']}; border-bottom: 2px solid {c['cyan']};}}"
        f"QTabBar::tab:hover:!selected {{background-color: {c['bg_panel']}; color: {c['text_primary']};}}"

        f"QScrollBar:vertical {{background: {c['bg_deep']}; width: 8px; border: none;}}"
        f"QScrollBar::handle:vertical {{background: {c['border_hi']}; border-radius: 4px; min-height: 20px;}}"
        f"QScrollBar::handle:vertical:hover {{background: {c['cyan_dim']};}}"
        f"QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{height: 0;}}"
        f"QScrollBar:horizontal {{background: {c['bg_deep']}; height: 8px; border: none;}}"
        f"QScrollBar::handle:horizontal {{background: {c['border_hi']}; border-radius: 4px;}}"

        f"QStatusBar {{background-color: {c['bg_deep']}; color: {c['text_muted']};"
        f"border-top: 1px solid {c['border']};"
        f"font-family: 'Consolas', monospace; font-size: 12px; padding: 3px 8px;}}"

        f"QLabel#appTitle {{font-family: 'Consolas', monospace;"
        f"font-size: 17px; font-weight: bold; color: {c['cyan']}; letter-spacing: 3px;}}"
        f"QLabel#appSubtitle {{font-family: 'Consolas', monospace;"
        f"font-size: 12px; color: {c['text_muted']}; letter-spacing: 2px;}}"
        f"QLabel#statVal {{font-family: 'Consolas', monospace; font-size: 32px; font-weight: bold;}}"
        f"QLabel#statKey {{font-family: 'Consolas', monospace; font-size: 11px;"
        f"letter-spacing: 2px; color: {c['text_muted']}; text-transform: uppercase;}}"
        f"QLabel#sectionTitle {{font-family: 'Consolas', monospace; font-size: 12px;"
        f"font-weight: bold; color: {c['cyan']}; letter-spacing: 2px;"
        f"padding: 6px 0 2px 0; border-bottom: 1px solid {c['border']}; margin-bottom: 4px;}}"
        f"QLabel#resultLbl {{font-family: 'Consolas', monospace;"
        f"font-size: 12px; color: {c['text_muted']}; padding: 0 8px;}}"
        f"QLabel#ledActive {{font-size: 12px; font-weight: bold; color: {c['green']};"
        f"letter-spacing: 1px; font-family: 'Consolas', monospace;}}"
        f"QLabel#ledIdle {{font-size: 12px; font-weight: bold; color: {c['red']};"
        f"letter-spacing: 1px; font-family: 'Consolas', monospace;}}"
        f"QLabel#clockLbl {{font-family: 'Consolas', monospace;"
        f"font-size: 14px; color: {c['amber']}; letter-spacing: 1px;}}"
    )


STYLE = _build_style(C)

SEVERITY_COLORS = {
    "LOW":      C["green"],
    "MEDIUM":   C["amber"],
    "HIGH":     C["orange"],
    "CRITICAL": C["red"],
}

COL_TIME   = 0
COL_TYPE   = 1
COL_RULE   = 2
COL_SEV    = 3
COL_SRC    = 4
COL_DST    = 5
COL_PORT   = 6
COL_PKTS   = 7
COL_LAYER  = 8

COL_HEADERS = [
    "TIMESTAMP", "TYPE", "RULE / SIGNATURE",
    "SEVERITY", "SOURCE IP", "TARGET IP",
    "PORT", "PACKETS", "ALGORITHM"
]


class NIDSMainWindow(QMainWindow):

    def __init__(self, packet_queue, alert_queue,
                 capture_controller, iface_list, iface_map=None,
                 net_scanner=None, hotspot_monitor=None):
        super().__init__()
        self.packet_queue       = packet_queue
        self.alert_queue        = alert_queue
        self.capture_controller = capture_controller
        self.iface_list         = iface_list
        self.iface_map          = iface_map or {n: n for n in iface_list}
        self._net_scanner      = net_scanner
        self._hotspot_monitor  = hotspot_monitor

        # Initialize confusion matrix analyzer for session analysis
        self.session_analyzer = None
        if ANALYZER_AVAILABLE:
            self.session_analyzer = ConfusionMatrixAnalyzer()

        self.bridge = SignalBridge()
        self.bridge.alert_received.connect(self._on_alert)
        self.bridge.packet_received.connect(self._on_packet)
        self.bridge.status_update.connect(self._on_status)

        self.packet_count = 0
        self.alert_count  = 0
        self.dos_count    = 0
        self.ddos_count   = 0
        self._running     = False
        self._all_alerts  = []
        self._rule_counters = {}
        self._rule_label_widgets = {}

        self._dark_mode = True   # start in dark mode

        self._setup_ui()
        self._start_queue_reader()

        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self._tick)
        self._stats_timer.start(1000)

    # ------------------------------------------------------------------ #
    #  UI SETUP                                                            #
    # ------------------------------------------------------------------ #

    def _setup_ui(self):
        self.setWindowTitle(
            "NIDS  //  Signature-Based Network Intrusion Detection System"
        )
        self.setMinimumSize(1400, 860)
        self.setStyleSheet(STYLE)

        root = QWidget()
        root.setStyleSheet(f"background-color: {C['bg_deep']};")
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header bar
        layout.addWidget(self._build_header())

        # Stat strip
        layout.addWidget(self._build_stat_strip())

        # Controls bar
        layout.addWidget(self._build_controls_bar())

        # Search bar
        layout.addWidget(self._build_search_bar())

        # Main content: sidebar + tabs
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet(
            f"QSplitter::handle {{ background: {C['border']}; }}"
        )
        self._splitter = splitter  # store for theme toggle
        splitter.addWidget(self._build_sidebar())
        splitter.addWidget(self._build_main_panel())
        splitter.setSizes([200, 1200])
        layout.addWidget(splitter, stretch=1)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self._update_status("SYSTEM READY  //  Select interface and start capture")

    # ------------------------------------------------------------------ #
    #  HEADER                                                              #
    # ------------------------------------------------------------------ #

    def _build_header(self):
        bar = QFrame()
        bar.setObjectName("headerBar")
        bar.setFixedHeight(52)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(16, 0, 16, 0)

        # Left — app identity
        left = QVBoxLayout()
        left.setSpacing(1)
        title = QLabel("NIDS  //  NETWORK INTRUSION DETECTION SYSTEM")
        title.setObjectName("appTitle")
        sub = QLabel(
            "SLIDING WINDOW RATE ANALYSIS  +  MULTI-SOURCE CORRELATION  "
            "//  SIGNATURE-BASED  //  REAL-TIME"
        )
        sub.setObjectName("appSubtitle")
        left.addWidget(title)
        left.addWidget(sub)
        lay.addLayout(left)

        lay.addStretch()

        # Right — live clock + status LED
        right = QHBoxLayout()
        right.setSpacing(16)

        self.led = QLabel("● IDLE")
        self.led.setObjectName("ledIdle")
        right.addWidget(self.led)

        self.clock_lbl = QLabel()
        self.clock_lbl.setObjectName("clockLbl")
        right.addWidget(self.clock_lbl)

        lay.addLayout(right)
        return bar

    # ------------------------------------------------------------------ #
    #  STAT STRIP                                                          #
    # ------------------------------------------------------------------ #

    def _build_stat_strip(self):
        strip = QFrame()
        strip.setObjectName("topbar")
        strip.setFixedHeight(76)
        lay = QHBoxLayout(strip)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(8)

        stats = [
            ("PACKETS CAPTURED", "packets_val", C["cyan"]),
            ("ALERTS TRIGGERED", "alerts_val",  C["amber"]),
            ("DoS DETECTED",     "dos_val",      C["orange"]),
            ("DDoS DETECTED",    "ddos_val",     C["red"]),
        ]

        for key, attr, color in stats:
            card = QFrame()
            card.setObjectName("statCard")
            card.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Preferred
            )
            cl = QVBoxLayout(card)
            cl.setContentsMargins(12, 4, 12, 4)
            cl.setSpacing(0)

            val = QLabel("0")
            val.setObjectName("statVal")
            val.setStyleSheet(f"color: {color};")
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)

            lbl = QLabel(key)
            lbl.setObjectName("statKey")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

            cl.addWidget(val)
            cl.addWidget(lbl)
            setattr(self, attr, val)
            lay.addWidget(card)

        return strip

    # ------------------------------------------------------------------ #
    #  CONTROLS BAR                                                        #
    # ------------------------------------------------------------------ #

    def _build_controls_bar(self):
        bar = QFrame()
        bar.setStyleSheet(
            f"background-color: {C['bg_panel']};"
            f"border-bottom: 1px solid {C['border']};"
        )
        self._controls_bar = bar  # store for theme toggle
        bar.setFixedHeight(46)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 6, 12, 6)
        lay.setSpacing(8)

        # Interface label + combo
        iface_lbl = QLabel("INTERFACE")
        iface_lbl.setStyleSheet(
            f"color: {C['text_muted']}; font-size: 10px; "
            f"letter-spacing: 1px; font-family: Consolas;"
        )
        self._iface_lbl = iface_lbl  # store for theme toggle
        lay.addWidget(iface_lbl)

        self.iface_combo = QComboBox()
        self.iface_combo.addItems(
            self.iface_list if self.iface_list else ["(default)"]
        )
        self.iface_combo.setMinimumWidth(300)
        # Auto-select best interface (WiFi/Ethernet preferred over VM/Loopback)
        self._auto_select_best_iface()
        lay.addWidget(self.iface_combo)

        lay.addSpacing(8)

        self.start_btn = QPushButton("▶  START")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.connect(self._start_capture)
        lay.addWidget(self.start_btn)

        self.stop_btn = QPushButton("■  STOP")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_capture)
        lay.addWidget(self.stop_btn)

        lay.addStretch()

        self.export_btn = QPushButton("⬇  EXPORT CSV")
        self.export_btn.setObjectName("exportBtn")
        self.export_btn.clicked.connect(self._export_csv)
        lay.addWidget(self.export_btn)

        self.clear_btn = QPushButton("✕  CLEAR")
        self.clear_btn.setObjectName("clearBtn")
        self.clear_btn.clicked.connect(self._clear_log)
        lay.addWidget(self.clear_btn)

        lay.addSpacing(4)

        self.theme_btn = QPushButton("☀")
        self.theme_btn.setObjectName("themeBtn")
        self.theme_btn.setToolTip("Toggle Dark / Light theme")
        self.theme_btn.setFixedWidth(38)
        self.theme_btn.clicked.connect(self._toggle_theme)
        lay.addWidget(self.theme_btn)

        return bar

    # ------------------------------------------------------------------ #
    #  SEARCH BAR                                                          #
    # ------------------------------------------------------------------ #

    def _build_search_bar(self):
        bar = QFrame()
        bar.setStyleSheet(
            f"background-color: {C['bg_deep']};"
            f"border-bottom: 1px solid {C['border']};"
        )
        self._search_bar = bar  # store for theme toggle
        bar.setFixedHeight(40)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 4, 12, 4)
        lay.setSpacing(8)

        srch_lbl = QLabel("⌕")
        srch_lbl.setStyleSheet(
            f"color: {C['cyan']}; font-size: 16px;"
        )
        self._search_icon = srch_lbl  # store for theme toggle
        lay.addWidget(srch_lbl)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText(
            "Filter by IP address, port, protocol, rule name, severity, algorithm..."
        )
        self.search_box.setMinimumWidth(380)
        self.search_box.textChanged.connect(self._apply_search)
        lay.addWidget(self.search_box)

        self.filter_col = QComboBox()
        self.filter_col.addItems([
            "ALL FIELDS", "SOURCE IP", "TARGET IP",
            "TYPE", "RULE NAME", "SEVERITY", "PORT", "ALGORITHM"
        ])
        self.filter_col.currentIndexChanged.connect(self._apply_search)
        lay.addWidget(self.filter_col)

        self.sev_filter = QComboBox()
        self.sev_filter.addItems(
            ["ALL SEVERITY", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
        self.sev_filter.currentIndexChanged.connect(self._apply_search)
        lay.addWidget(self.sev_filter)

        lay.addStretch()

        self.clr_srch_btn = QPushButton("RESET")
        self.clr_srch_btn.setObjectName("clearBtn")
        self.clr_srch_btn.clicked.connect(self._clear_search)
        lay.addWidget(self.clr_srch_btn)

        self.result_lbl = QLabel("SHOWING ALL ALERTS")
        self.result_lbl.setObjectName("resultLbl")
        lay.addWidget(self.result_lbl)

        return bar

    # ------------------------------------------------------------------ #
    #  SIDEBAR                                                             #
    # ------------------------------------------------------------------ #

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setMinimumWidth(185)
        sidebar.setMaximumWidth(240)
        lay = QVBoxLayout(sidebar)
        lay.setContentsMargins(10, 12, 10, 12)
        lay.setSpacing(4)

        # Section: System
        sys_lbl = QLabel("SYSTEM STATUS")
        sys_lbl.setObjectName("sectionTitle")
        lay.addWidget(sys_lbl)

        self._sys_rows = {}
        self._sidebar_key_labels = []  # store for theme toggle
        for key, val in [
            ("MODE",      "SIGNATURE-BASED"),
            ("ALGORITHM", "SLIDING WINDOW"),
            ("CORR",      "MULTI-SOURCE"),
            ("EVIDENCE",  "PCAP + JSON"),
            ("ALERTS",    "TELEGRAM"),
        ]:
            row = QHBoxLayout()
            k = QLabel(key)
            k.setStyleSheet(
                f"color: {C['text_muted']}; font-size: 9px; "
                f"letter-spacing: 1px;"
            )
            self._sidebar_key_labels.append(k)  # store for theme toggle
            v = QLabel(val)
            v.setStyleSheet(
                f"color: {C['cyan']}; font-size: 11px; "
                f"font-weight: bold;"
            )
            v.setAlignment(Qt.AlignmentFlag.AlignRight)
            row.addWidget(k)
            row.addStretch()
            row.addWidget(v)
            lay.addLayout(row)
            self._sys_rows[key] = v

        lay.addSpacing(10)

        # Section: Rule detections
        rule_lbl = QLabel("RULE DETECTIONS")
        rule_lbl.setObjectName("sectionTitle")
        lay.addWidget(rule_lbl)

        self._rule_panel_layout = QVBoxLayout()
        self._rule_panel_layout.setSpacing(1)

        scroll_widget = QWidget()
        scroll_widget.setLayout(self._rule_panel_layout)
        scroll_widget.setStyleSheet("background: transparent;")

        scroll = QScrollArea()
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        scroll.setStyleSheet(
            f"QScrollArea {{ border: none; background: transparent; }}"
        )
        lay.addWidget(scroll, stretch=1)

        # Section: Recent alert
        recent_lbl = QLabel("LAST ALERT")
        recent_lbl.setObjectName("sectionTitle")
        lay.addWidget(recent_lbl)

        self.last_alert_lbl = QLabel("—")
        self.last_alert_lbl.setStyleSheet(
            f"color: {C['text_primary']}; font-size: 12px;"
        )
        self.last_alert_lbl.setWordWrap(True)
        lay.addWidget(self.last_alert_lbl)

        return sidebar

    # ------------------------------------------------------------------ #
    #  MAIN PANEL                                                          #
    # ------------------------------------------------------------------ #

    def _build_main_panel(self):
        panel = QWidget()
        panel.setStyleSheet(f"background: {C['bg_panel']};")
        self._main_panel = panel  # store for theme toggle
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.tabs.addTab(self._build_alert_tab(),    "  ALERTS  ")
        self.tabs.addTab(self._build_packet_tab(),   "  PACKET LOG  ")
        self.tabs.addTab(self._build_evidence_tab(), "  EVIDENCE  ")

        # Feature 1: Network Scanner tab
        if NEW_TABS_AVAILABLE:
            self.scanner_tab = NetworkScannerTab()
            if hasattr(self, '_net_scanner') and self._net_scanner:
                self.scanner_tab.set_scanner(self._net_scanner)
            self.tabs.addTab(self.scanner_tab, "  🔍 SCANNER  ")

            # Feature 2: Hotspot Monitor tab
            self.hotspot_tab = HotspotMonitorTab()
            if hasattr(self, '_hotspot_monitor') and self._hotspot_monitor:
                self.hotspot_tab.set_monitor(self._hotspot_monitor)
            self.tabs.addTab(self.hotspot_tab, "  📡 HOTSPOT  ")
        lay.addWidget(self.tabs)

        return panel

    def _build_alert_tab(self):
        self.alert_table = QTableWidget(0, len(COL_HEADERS))
        self.alert_table.setHorizontalHeaderLabels(COL_HEADERS)
        hdr = self.alert_table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setDefaultSectionSize(120)
        hdr.setSectionResizeMode(COL_RULE, QHeaderView.ResizeMode.Stretch)
        self.alert_table.verticalHeader().setVisible(False)
        self.alert_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.alert_table.setShowGrid(True)
        self.alert_table.setWordWrap(False)
        self.alert_table.verticalHeader().setDefaultSectionSize(28)
        return self.alert_table

    def _build_packet_tab(self):
        self.packet_log = QPlainTextEdit()
        self.packet_log.setReadOnly(True)
        self.packet_log.setMaximumBlockCount(1000)
        self.packet_log.setStyleSheet(
            f"color: {C['text_primary']}; "
            f"background-color: {C['bg_deep']};"
        )
        return self.packet_log

    def _build_evidence_tab(self):
        frame = QWidget()
        lay   = QVBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 0)
        info  = QLabel(
            "  PCAP + JSON evidence saved to attacks/ on each detection"
        )
        info.setStyleSheet(
            f"color: {C['text_muted']}; font-size: 10px; "
            f"padding: 6px; border-bottom: 1px solid {C['border']};"
        )
        lay.addWidget(info)
        self.evidence_log = QPlainTextEdit()
        self.evidence_log.setReadOnly(True)
        self.evidence_log.setMaximumBlockCount(300)
        lay.addWidget(self.evidence_log)
        return frame

    # ------------------------------------------------------------------ #
    #  CAPTURE CONTROL                                                     #
    # ------------------------------------------------------------------ #

    def _auto_select_best_iface(self):
        """
        Automatically select the best interface in the dropdown.
        Prefers WiFi > Ethernet > Hotspot > others.
        Skips VM adapters, Loopback, and VPN.
        """
        try:
            from packet_capture import get_best_interface
            best = get_best_interface(self.iface_map)
            if best and best in self.iface_list:
                idx = self.iface_list.index(best)
                self.iface_combo.setCurrentIndex(idx)
                return
            # Fallback: find first WiFi or Ethernet in list
            for i, label in enumerate(self.iface_list):
                label_low = label.lower()
                if "[wifi]" in label_low or "[ethernet]" in label_low:
                    self.iface_combo.setCurrentIndex(i)
                    return
        except Exception:
            pass  # use default selection

    def _start_capture(self):
        selected = self.iface_combo.currentText()
        dev      = self.iface_map.get(selected, selected)
        iface    = None if selected == "(default)" else dev
        self._capture_start_time = time.time()
        
        # Initialize new analyzer for this session
        if ANALYZER_AVAILABLE:
            self.session_analyzer = ConfusionMatrixAnalyzer(
                session_name=datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            )
        
        self.capture_controller.start(iface)
        self._running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.led.setText("● LIVE")
        self.led.setObjectName("ledActive")
        self.led.setStyleSheet(
            f"color: {C['green']}; font-size: 10px; "
            f"font-weight: bold; letter-spacing: 1px; "
            f"font-family: Consolas;"
        )
        self._sys_rows["MODE"].setText("CAPTURING")
        self._sys_rows["MODE"].setStyleSheet(
            f"color: {C['green']}; font-size: 9px; font-weight: bold;"
        )
        self._update_status(
            f"CAPTURE ACTIVE  //  Interface: {selected}"
        )

    def _stop_capture(self):
        self.capture_controller.stop()
        self._running          = False
        self._capture_end_time = time.time()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._show_session_summary()
        
        # Show analysis dialog
        if ANALYZER_AVAILABLE and self.session_analyzer:
            try:
                dialog = AnalysisDialog(self.session_analyzer, parent=self)
                dialog.exec()
            except Exception as e:
                logging.getLogger("GUI").debug(f"Analysis dialog error: {e}")
        
        self.led.setText("● IDLE")
        self.led.setStyleSheet(
            f"color: {C['red']}; font-size: 10px; "
            f"font-weight: bold; letter-spacing: 1px; "
            f"font-family: Consolas;"
        )
        self._sys_rows["MODE"].setText("STOPPED")
        self._sys_rows["MODE"].setStyleSheet(
            f"color: {C['red']}; font-size: 9px; font-weight: bold;"
        )
        self._update_status("CAPTURE STOPPED")

    def _apply_theme_to_new_tabs(self, p: dict):
        """
        Delegate theme to each new tab via its apply_theme(p) method.
        This is the correct approach — each tab class owns its own theming.
        """
        for tab_attr in ["scanner_tab", "hotspot_tab"]:
            tab = getattr(self, tab_attr, None)
            if tab and hasattr(tab, "apply_theme"):
                try:
                    tab.apply_theme(p)
                except Exception as e:
                    import logging
                    logging.getLogger("GUI").debug(
                        "apply_theme failed for " + tab_attr + ": " + str(e)
                    )


    def _toggle_theme(self):
        """
        Switch between dark and light theme.
        Updates main stylesheet AND all inline-styled child widgets.
        """
        self._dark_mode = not self._dark_mode
        p = C if self._dark_mode else C_LIGHT   # active palette

        # 1. Main window stylesheet
        self.setStyleSheet(_build_style(p))

        # 2. Root widget background
        self.centralWidget().setStyleSheet(
            f"background-color: {p['bg_deep']};"
        )

        # 3. Splitter handle
        if hasattr(self, '_splitter'):
            self._splitter.setStyleSheet(
                f"QSplitter::handle {{ background: {p['border']}; }}"
            )

        # 4. Stat card value colours (hardcoded per card)
        for attr, color_key in [
            ('packets_val', 'cyan'),
            ('alerts_val',  'amber'),
            ('dos_val',     'orange'),
            ('ddos_val',    'red'),
        ]:
            if hasattr(self, attr):
                getattr(self, attr).setStyleSheet(f"color: {p[color_key]};")

        # 5. Sidebar system status labels
        for key, lbl in self._sys_rows.items():
            lbl.setStyleSheet(
                f"color: {p['cyan']}; font-size: 11px; font-weight: bold;"
            )

        # 6. Sidebar label + value rows (muted key labels)
        for lbl in getattr(self, '_sidebar_key_labels', []):
            lbl.setStyleSheet(
                f"color: {p['text_muted']}; font-size: 11px; letter-spacing: 1px;"
            )

        # 7. Last alert label
        if hasattr(self, 'last_alert_lbl'):
            self.last_alert_lbl.setStyleSheet(
                f"color: {p['text_primary']}; font-size: 12px;"
            )

        # 8. Controls bar background
        if hasattr(self, '_controls_bar'):
            self._controls_bar.setStyleSheet(
                f"background-color: {p['bg_panel']};"
                f"border-bottom: 1px solid {p['border']};"
            )

        # 9. Search bar background
        if hasattr(self, '_search_bar'):
            self._search_bar.setStyleSheet(
                f"background-color: {p['bg_deep']};"
                f"border-bottom: 1px solid {p['border']};"
            )

        # 10. Interface label in controls bar
        if hasattr(self, '_iface_lbl'):
            self._iface_lbl.setStyleSheet(
                f"color: {p['text_muted']}; font-size: 10px; "
                f"letter-spacing: 1px; font-family: Consolas;"
            )

        # 11. Packet log colour
        if hasattr(self, 'packet_log'):
            self.packet_log.setStyleSheet(
                f"color: {p['text_primary']}; "
                f"background-color: {p['bg_deep']};"
            )

        # 12. Evidence info label
        if hasattr(self, '_evidence_info_lbl'):
            self._evidence_info_lbl.setStyleSheet(
                f"color: {p['text_muted']}; font-size: 12px; "
                f"padding: 6px; border-bottom: 1px solid {p['border']};"
            )

        # 13. Main panel background
        if hasattr(self, '_main_panel'):
            self._main_panel.setStyleSheet(
                f"background: {p['bg_panel']};"
            )

        # 14. Search icon label
        if hasattr(self, '_search_icon'):
            self._search_icon.setStyleSheet(
                f"color: {p['cyan']}; font-size: 16px;"
            )

        # 15. Theme button icon
        self.theme_btn.setText("☀" if self._dark_mode else "🌙")
        self._apply_theme_to_new_tabs(p)
        self._update_status(
            "THEME: DARK" if self._dark_mode else "THEME: LIGHT"
        )

    def _clear_log(self):
        self._all_alerts = []
        self.alert_table.setRowCount(0)
        self.packet_log.clear()
        self.evidence_log.clear()
        self._rule_counters = {}
        for w in self._rule_label_widgets.values():
            w.deleteLater()
        self._rule_label_widgets = {}
        self.last_alert_lbl.setText("—")
        self.result_lbl.setText("SHOWING ALL ALERTS")

    # ------------------------------------------------------------------ #
    #  EXPORT CSV                                                          #
    # ------------------------------------------------------------------ #

    def _show_session_summary(self):
        """Session summary in a fully themed QDialog matching NIDS palette."""
        from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout,
                                      QLabel, QPushButton, QFrame)
        from PyQt6.QtCore import Qt

        duration = 0
        if hasattr(self, "_capture_start_time") and self._capture_start_time:
            duration = self._capture_end_time - self._capture_start_time

        def _int(w):
            try:    return int(w.text().replace(",","").replace("+",""))
            except: return 0

        total_pkts   = _int(self.packets_val)  if hasattr(self,"packets_val")  else 0
        total_alerts = _int(self.alerts_val)   if hasattr(self,"alerts_val")   else 0
        dos_count    = _int(self.dos_val)      if hasattr(self,"dos_val")      else 0
        ddos_count   = _int(self.ddos_val)     if hasattr(self,"ddos_val")     else 0
        mins = int(duration // 60); secs = int(duration % 60)
        pps  = (total_pkts / duration) if duration > 0 else 0

        top_src = "N/A"
        if hasattr(self,"alert_table") and self.alert_table.rowCount() > 0:
            src_counts = {}
            for row in range(self.alert_table.rowCount()):
                item = self.alert_table.item(row, 4)
                if item:
                    ip = item.text()
                    src_counts[ip] = src_counts.get(ip, 0) + 1
            if src_counts:
                ts_ip = max(src_counts, key=src_counts.get)
                top_src = ts_ip + " (" + str(src_counts[ts_ip]) + " alerts)"

        # Use active palette
        p      = C if self._dark_mode else C_LIGHT
        bg     = p["bg_deep"]
        card   = p["bg_card"]
        text   = p["text_primary"]
        td     = p["text_muted"]
        border = p["border"]
        cyan   = p["cyan"]
        amber  = p["amber"]

        dlg = QDialog(self)
        dlg.setWindowTitle("Session Summary")
        dlg.setMinimumWidth(400)
        dlg.setStyleSheet(
            "QDialog { background:" + bg + "; }"
            "QLabel  { color:" + text + "; font-family:Consolas; }"
        )

        lay = QVBoxLayout(dlg)
        lay.setSpacing(0)
        lay.setContentsMargins(0, 0, 0, 0)

        # Title bar
        title_lbl = QLabel("  SESSION COMPLETE")
        title_lbl.setStyleSheet(
            "background:" + card + "; color:" + cyan + "; "
            "font-family:Consolas; font-size:13px; font-weight:bold; "
            "padding:10px 16px; border-bottom:1px solid " + border + ";"
        )
        lay.addWidget(title_lbl)

        # Stats grid
        content = QFrame()
        content.setStyleSheet(
            "QFrame { background:" + bg + "; padding:16px; }"
        )
        cl = QVBoxLayout(content)
        cl.setSpacing(6)

        rows = [
            ("Duration",          str(mins) + "m " + str(secs) + "s",    cyan),
            ("Packets captured",  "{:,}".format(total_pkts),              text),
            ("Avg packet rate",   "{:.0f} pkt/s".format(pps),             text),
            ("Total alerts",      str(total_alerts),
             amber if total_alerts > 0 else text),
            ("  DoS detected",    str(dos_count),
             "#f85149" if dos_count > 0 else td),
            ("  DDoS detected",   str(ddos_count),
             "#f85149" if ddos_count > 0 else td),
            ("Top attacker IP",   top_src,
             "#f85149" if top_src != "N/A" else td),
        ]

        for label, value, val_color in rows:
            row_w = QHBoxLayout()
            row_w.setContentsMargins(0, 0, 0, 0)
            lbl = QLabel(label)
            lbl.setStyleSheet(
                "color:" + td + "; font-family:Consolas; font-size:12px;"
            )
            lbl.setFixedWidth(180)
            val = QLabel(value)
            val.setStyleSheet(
                "color:" + val_color + "; font-family:Consolas; "
                "font-size:12px; font-weight:bold;"
            )
            row_w.addWidget(lbl)
            row_w.addWidget(val)
            row_w.addStretch()
            cl.addLayout(row_w)

        lay.addWidget(content)

        # Close button
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(16, 8, 16, 12)
        btn_row.addStretch()
        close_btn = QPushButton("CLOSE")
        close_btn.setStyleSheet(
            "QPushButton { background:transparent; color:" + cyan + "; "
            "border:1px solid " + cyan + "; padding:6px 24px; "
            "font-family:Consolas; font-size:11px; font-weight:bold; "
            "border-radius:3px; }"
            "QPushButton:hover { background:" + cyan + "; color:" + bg + "; }"
        )
        close_btn.clicked.connect(dlg.accept)
        btn_row.addWidget(close_btn)
        lay.addLayout(btn_row)

        dlg.exec()

    def _export_csv(self):
        if not self._all_alerts:
            QMessageBox.information(self, "Export", "No alerts to export.")
            return
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Alerts",
            f"nids_alerts_{ts}.csv",
            "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(COL_HEADERS)
                csv.writer(f).writerows(self._all_alerts)
            QMessageBox.information(
                self, "Exported",
                f"Saved {len(self._all_alerts)} alerts to:\n{path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    # ------------------------------------------------------------------ #
    #  SEARCH                                                              #
    # ------------------------------------------------------------------ #

    _COL_MAP = {
        "ALL FIELDS": None, "SOURCE IP": COL_SRC, "TARGET IP": COL_DST,
        "TYPE": COL_TYPE, "RULE NAME": COL_RULE,
        "SEVERITY": COL_SEV, "PORT": COL_PORT, "ALGORITHM": COL_LAYER,
    }

    def _on_tab_changed(self, idx):
        hints = [
            "Filter by IP, port, rule, severity, algorithm...",
            "Filter packet log by IP, protocol, flags...",
            "Filter evidence log by IP, rule, attack type...",
        ]
        self.search_box.setPlaceholderText(
            hints[idx] if idx < len(hints) else "Filter..."
        )
        self._apply_search()

    def _apply_search(self):
        idx = self.tabs.currentIndex()
        if idx == 0:
            self._search_alerts()
        elif idx == 1:
            self._search_text(self.packet_log)
        elif idx == 2:
            self._search_text(self.evidence_log)

    def _search_alerts(self):
        q       = self.search_box.text().strip().lower()
        col     = self._COL_MAP.get(self.filter_col.currentText())
        sev     = self.sev_filter.currentText()
        use_sev = sev != "ALL SEVERITY"

        self.alert_table.setRowCount(0)
        vis = 0

        for cells in self._all_alerts:
            if use_sev and cells[COL_SEV] != sev:
                continue
            if q:
                src = cells[col].lower() if col is not None \
                    else " ".join(cells).lower()
                if q not in src:
                    continue
            row   = self.alert_table.rowCount()
            self.alert_table.insertRow(row)
            color = QColor(SEVERITY_COLORS.get(cells[COL_SEV], C["text_primary"]))
            for c, txt in enumerate(cells):
                item = QTableWidgetItem(txt)
                item.setForeground(color)
                self.alert_table.setItem(row, c, item)
            vis += 1

        total = len(self._all_alerts)
        self.result_lbl.setText(
            f"SHOWING {vis} / {total}" if (q or use_sev)
            else f"SHOWING ALL  {total}"
        )

    def _search_text(self, w: QPlainTextEdit):
        q = self.search_box.text().strip().lower()
        lines = w.toPlainText().splitlines()
        if not q:
            self.result_lbl.setText(f"SHOWING ALL  {len(lines)} LINES")
            return
        matched = [l for l in lines if q in l.lower()]
        w.setPlainText("\n".join(matched))
        self.result_lbl.setText(
            f"SHOWING {len(matched)} / {len(lines)} LINES"
        )

    def _clear_search(self):
        self.search_box.clear()
        self.filter_col.setCurrentIndex(0)
        self.sev_filter.setCurrentIndex(0)
        self._apply_search()

    # ------------------------------------------------------------------ #
    #  QUEUE READER                                                        #
    # ------------------------------------------------------------------ #

    def _start_queue_reader(self):
        def reader():
            while True:
                try:
                    item = self.alert_queue.get(timeout=0.2)
                    if item["__type"] == "alert":
                        self.bridge.alert_received.emit(item)
                    elif item["__type"] == "packet":
                        self.bridge.packet_received.emit(item)
                except queue.Empty:
                    pass
        threading.Thread(target=reader, daemon=True).start()

    # ------------------------------------------------------------------ #
    #  SIGNAL HANDLERS                                                     #
    # ------------------------------------------------------------------ #

    def _on_alert(self, alert: dict):
        self.alert_count += 1
        atype = alert.get("type", "?")
        if "DDoS" in atype:
            self.ddos_count += 1
        else:
            self.dos_count += 1

        # Add to session analyzer for confusion matrix
        if self.session_analyzer and self._running:
            try:
                self.session_analyzer.add_detection(alert, is_real_attack=True)
            except Exception as e:
                logging.getLogger("GUI").debug(f"Analyzer error: {e}")

        ts   = time.strftime(
            "%H:%M:%S",
            time.localtime(alert.get("timestamp", time.time()))
        )
        sev  = alert.get("severity", "?")
        port = alert.get("dst_port", 0)
        port_s = str(port) if port else "—"

        rule = alert.get("rule_name", "?")
        layer = (
            "MULTI-SOURCE CORR."
            if ("DDoS" in atype or "Multi-Source" in rule)
            else "SLIDING WINDOW"
        )

        cells = [
            ts, atype, rule, sev,
            alert.get("source", "?"),
            alert.get("target", "?"),
            port_s,
            str(alert.get("packet_count", 0)),
            layer,
        ]

        self._all_alerts.append(cells)
        self._update_rule_counter(rule, sev)

        # Last alert sidebar
        self.last_alert_lbl.setText(
            f"{ts}\n{sev}  {rule}\n"
            f"{alert.get('source','?')} → {alert.get('target','?')}"
        )
        self.last_alert_lbl.setStyleSheet(
            f"color: {SEVERITY_COLORS.get(sev, C['text_primary'])}; "
            f"font-size: 12px;"
        )

        # Add to table if passes filter
        q       = self.search_box.text().strip().lower()
        col     = self._COL_MAP.get(self.filter_col.currentText())
        sev_flt = self.sev_filter.currentText()
        use_sev = sev_flt != "ALL SEVERITY"

        ok = True
        if use_sev and cells[COL_SEV] != sev_flt:
            ok = False
        if ok and q:
            src = cells[col].lower() if col is not None \
                else " ".join(cells).lower()
            ok = q in src

        if ok:
            row   = self.alert_table.rowCount()
            self.alert_table.insertRow(row)
            color = QColor(SEVERITY_COLORS.get(sev, C["text_primary"]))
            for c, txt in enumerate(cells):
                item = QTableWidgetItem(txt)
                item.setForeground(color)
                self.alert_table.setItem(row, c, item)
            self.alert_table.scrollToBottom()

        total = len(self._all_alerts)
        vis   = self.alert_table.rowCount()
        self.result_lbl.setText(
            f"SHOWING {vis} / {total}"
            if (q or use_sev) else f"SHOWING ALL  {total}"
        )

        self.evidence_log.appendPlainText(
            f"[{ts}]  {sev:<8}  {rule:<30}  "
            f"{alert.get('source','?')} -> "
            f"{alert.get('target','?')}:{port_s}  //  {layer}"
        )

    def _on_packet(self, pkt: dict):
        self.packet_count += 1
        
        # Track packet count in analyzer
        if self.session_analyzer:
            self.session_analyzer.total_packets += 1
        
        ts   = time.strftime(
            "%H:%M:%S",
            time.localtime(pkt.get("timestamp", time.time()))
        )
        port = pkt.get("dst_port", 0)
        p_s  = f":{port}" if port else ""
        flags_str = pkt.get('flags') or ''
        self.packet_log.appendPlainText(
        f"[{ts}]  {pkt.get('protocol','?'):<5}  "
        f"{pkt.get('src','?'):<18}  ->  "
        f"{pkt.get('dst','?'):<18}{p_s:<7}  "
        f"flags=[{flags_str:<4}]"
        )
    def _on_status(self, msg: str):
        self._update_status(msg)

    # ------------------------------------------------------------------ #
    #  SIDEBAR RULE COUNTER                                                #
    # ------------------------------------------------------------------ #

    def _update_rule_counter(self, rule_name: str, severity: str):
        self._rule_counters[rule_name] = \
            self._rule_counters.get(rule_name, 0) + 1
        count = self._rule_counters[rule_name]
        color = SEVERITY_COLORS.get(severity, C["text_primary"])

        if rule_name not in self._rule_label_widgets:
            row = QHBoxLayout()
            row.setContentsMargins(0, 1, 0, 1)

            # Truncate long rule names
            short = rule_name[:18] + ".." if len(rule_name) > 20 else rule_name
            k = QLabel(short)
            k.setStyleSheet(
                f"color: {C['text_muted']}; font-size: 11px;"
            )
            k.setFixedWidth(120)

            v = QLabel(f"{count:>4}")
            v.setStyleSheet(
                f"color: {color}; font-size: 12px; font-weight: bold;"
            )
            v.setAlignment(Qt.AlignmentFlag.AlignRight)

            row.addWidget(k)
            row.addWidget(v)

            container = QWidget()
            container.setLayout(row)
            container.setStyleSheet(
                f"border-bottom: 1px solid {C['border']};"
            )
            self._rule_panel_layout.addWidget(container)
            self._rule_label_widgets[rule_name] = v
        else:
            self._rule_label_widgets[rule_name].setText(f"{count:>4}")
            self._rule_label_widgets[rule_name].setStyleSheet(
                f"color: {color}; font-size: 12px; font-weight: bold;"
            )

    # ------------------------------------------------------------------ #
    #  TICK — clock + stats refresh                                        #
    # ------------------------------------------------------------------ #

    def _tick(self):
        self.clock_lbl.setText(
            time.strftime("%Y-%m-%d  %H:%M:%S")
        )
        self.packets_val.setText(f"{self.packet_count:,}")
        self.alerts_val.setText(f"{self.alert_count:,}")
        self.dos_val.setText(f"{self.dos_count:,}")
        self.ddos_val.setText(f"{self.ddos_count:,}")

    def _update_status(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.status_bar.showMessage(f"[{ts}]  {msg}")


# ------------------------------------------------------------------ #
#  LAUNCHER                                                            #
# ------------------------------------------------------------------ #

def launch_gui(packet_queue, alert_queue,
               capture_controller, iface_list, iface_map=None,
               net_scanner=None, hotspot_monitor=None):
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = NIDSMainWindow(
        packet_queue, alert_queue,
        capture_controller, iface_list, iface_map,
        net_scanner=net_scanner,
        hotspot_monitor=hotspot_monitor,
    )
    window.show()
    sys.exit(app.exec())