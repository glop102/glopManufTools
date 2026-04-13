"""
DiscoveryApplet — system tray icon that shows discovered mDNS hosts in a window.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QAction, QColor, QFont, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QScrollArea,
    QSystemTrayIcon,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from discovery_applet.worker import DiscoveryWorker

logger = logging.getLogger("discovery_applet.applet")


def _fallback_icon() -> QIcon:
    """Draw a small coloured dot as a fallback when no theme icon is available."""
    pixmap = QPixmap(22, 22)
    pixmap.fill(Qt.GlobalColor.transparent)
    from PyQt6.QtGui import QPainter
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor("#4a9eff"))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(3, 3, 16, 16)
    painter.end()
    return QIcon(pixmap)


class MainWindow(QMainWindow):
    """Full application window showing discovered hosts with a menu bar for scanner controls."""

    def __init__(self, worker: DiscoveryWorker) -> None:
        super().__init__()
        self._worker = worker
        self.setWindowTitle("Discovery")
        self.setMinimumSize(500, 400)

        # Menu bar
        self._scanners_menu = QMenu("Scanners", self)
        self.menuBar().addMenu(self._scanners_menu)

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        layout.addWidget(self._scroll)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(2)
        self._tree.setHeaderLabels(["Name", "Detail"])
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._tree.setIndentation(16)
        self._scroll.setWidget(self._tree)

        self._placeholder = QLabel("No hosts discovered")
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder.setStyleSheet("color: grey; padding: 16px;")
        layout.addWidget(self._placeholder)

        self._tree.hide()

    def closeEvent(self, event) -> None:
        """Hide instead of closing so the app stays alive in the tray."""
        event.ignore()
        self.hide()

    def update_hosts(self, hosts: dict[str, dict]) -> None:
        """Rebuild the tree from the current hosts dict."""
        self._tree.clear()

        if not hosts:
            self._tree.hide()
            self._placeholder.show()
            return

        self._placeholder.hide()
        self._tree.show()

        for key, host in hosts.items():
            hostname = host.get("hostname", key).rstrip(".")
            interface = host.get("interface", "")

            top = QTreeWidgetItem([hostname, f"[{interface}]"])
            bold = QFont()
            bold.setBold(True)
            top.setFont(0, bold)
            top.setData(0, Qt.ItemDataRole.UserRole, key)

            # Addresses child
            addresses: list[str] = host.get("addresses", [])
            addr_node = QTreeWidgetItem(["Addresses", f"{len(addresses)}"])
            addr_node.setForeground(0, QColor("grey"))
            for addr in addresses:
                addr_node.addChild(QTreeWidgetItem([addr, ""]))
            top.addChild(addr_node)

            # Services child
            services: list[dict] = host.get("services", [])
            svc_node = QTreeWidgetItem(["Services", f"{len(services)}"])
            svc_node.setForeground(0, QColor("grey"))
            for svc in services:
                stype = svc.get("service_type", "")
                port = svc.get("port", "")
                instance = svc.get("instance_name", "")
                svc_item = QTreeWidgetItem([instance or stype, f"{stype} :{port}"])
                txt: dict = svc.get("txt", {})
                for k, v in txt.items():
                    svc_item.addChild(QTreeWidgetItem([k, str(v)]))
                svc_node.addChild(svc_item)
            top.addChild(svc_node)

            self._tree.addTopLevelItem(top)
            top.setExpanded(True)

        self._tree.expandToDepth(0)
        self._tree.resizeColumnToContents(0)

    def update_scanners(self, running: list[str], builtins: list[str]) -> None:
        """Rebuild the Scanners menu from the current server state."""
        self._scanners_menu.clear()
        for name in running:
            action = QAction(f"Stop {name}", self)
            action.triggered.connect(lambda checked, n=name: self._worker.stop_scanner(n))
            self._scanners_menu.addAction(action)
        startable = [b for b in builtins if b not in running]
        if startable:
            if running:
                self._scanners_menu.addSeparator()
            for name in startable:
                action = QAction(f"Start {name}", self)
                action.triggered.connect(lambda checked, n=name: self._worker.start_builtin_scanner(n))
                self._scanners_menu.addAction(action)


class DiscoveryApplet(QSystemTrayIcon):
    """System tray icon; left-click toggles the main window."""

    def __init__(self) -> None:
        icon = QIcon.fromTheme("network-wired")
        if icon.isNull():
            icon = _fallback_icon()
        super().__init__(icon)

        self._hosts: dict[str, dict] = {}

        # Worker thread
        self.worker = DiscoveryWorker()
        self.worker.hosts_updated.connect(self._on_host_updated)
        self.worker.hosts_removed.connect(self._on_hosts_removed)
        self.worker.status_changed.connect(self._on_status_changed)
        self.worker.start()

        # Main window — created but not shown
        self._window = MainWindow(worker=self.worker)
        self.worker.scanners_changed.connect(self._window.update_scanners)

        self.activated.connect(self._on_activated)
        self._update_tooltip()

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @pyqtSlot(QSystemTrayIcon.ActivationReason)
    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self._window.isVisible():
                self._window.hide()
            else:
                self._window.show()
                self._window.raise_()
                self._window.activateWindow()

    def _on_host_updated(self, key: str, host: dict) -> None:
        self._hosts[key] = host
        self._update_tooltip()
        self._window.update_hosts(self._hosts)

    def _on_hosts_removed(self, keys: list) -> None:
        for key in keys:
            self._hosts.pop(key, None)
        self._update_tooltip()
        self._window.update_hosts(self._hosts)

    def _on_status_changed(self, status: str) -> None:
        logger.info("Discovery status: %s", status)
        self.setToolTip(f"Discovery — {status}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_tooltip(self) -> None:
        n = len(self._hosts)
        self.setToolTip(f"{n} host{'s' if n != 1 else ''} discovered")
