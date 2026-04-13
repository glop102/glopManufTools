"""
DiscoveryApplet — system tray icon showing per-scanner widgets in a scrollable window.
"""

from __future__ import annotations

import json
import logging

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QAction, QColor, QFont, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSystemTrayIcon,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from discovery.scanners.mdns import MDNSHostData
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


# ─── Interface dropdown ───────────────────────────────────────────────────────

class _InterfaceMenu(QMenu):
    """QMenu that stays open when a checkable action is toggled."""

    def mouseReleaseEvent(self, event) -> None:
        action = self.activeAction()
        if action and action.isCheckable():
            action.toggle()
            action.triggered.emit(action.isChecked())
            # Do not call super() — prevents the menu from closing
        else:
            super().mouseReleaseEvent(event)


# ─── Results widgets ──────────────────────────────────────────────────────────

class ScannerResultsWidget(QWidget):
    """Base class for the per-scanner results view."""

    def handle_results_updated(self, key: str, result: dict) -> None:
        raise NotImplementedError

    def handle_results_removed(self, keys: list[str]) -> None:
        raise NotImplementedError


class GenericResultsWidget(ScannerResultsWidget):
    """Shows any scanner's results as an expandable key → field tree."""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._tree = QTreeWidget()
        self._tree.setColumnCount(2)
        self._tree.setHeaderLabels(["Key", "Value"])
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._tree)
        self._items: dict[str, QTreeWidgetItem] = {}

    def handle_results_updated(self, key: str, result: dict) -> None:
        if key in self._items:
            top = self._items[key]
            top.takeChildren()
        else:
            top = QTreeWidgetItem([key, ""])
            self._tree.addTopLevelItem(top)
            self._items[key] = top

        for k, v in result.items():
            top.addChild(QTreeWidgetItem([str(k), v if isinstance(v, str) else json.dumps(v)]))
        top.setExpanded(True)

    def handle_results_removed(self, keys: list[str]) -> None:
        for key in keys:
            item = self._items.pop(key, None)
            if item is not None:
                self._tree.takeTopLevelItem(self._tree.indexOfTopLevelItem(item))


class MDNSResultsWidget(ScannerResultsWidget):
    """Shows MDNSHostData results with hostname, addresses, and services."""

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._tree = QTreeWidget()
        self._tree.setColumnCount(2)
        self._tree.setHeaderLabels(["Name", "Detail"])
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._tree.setIndentation(16)
        layout.addWidget(self._tree)
        self._items: dict[str, QTreeWidgetItem] = {}

    def handle_results_updated(self, key: str, result: dict) -> None:
        host = MDNSHostData.model_validate(result)
        hostname = host.hostname.rstrip(".")

        if key in self._items:
            top = self._items[key]
            top.setText(0, hostname)
            top.setText(1, f"[{host.interface}]")
            top.takeChildren()
        else:
            top = QTreeWidgetItem([hostname, f"[{host.interface}]"])
            bold = QFont()
            bold.setBold(True)
            top.setFont(0, bold)
            top.setData(0, Qt.ItemDataRole.UserRole, key)
            self._tree.addTopLevelItem(top)
            self._items[key] = top

        addr_node = QTreeWidgetItem(["Addresses", str(len(host.addresses))])
        addr_node.setForeground(0, QColor("grey"))
        for addr in host.addresses:
            addr_node.addChild(QTreeWidgetItem([addr, ""]))
        top.addChild(addr_node)

        svc_node = QTreeWidgetItem(["Services", str(len(host.services))])
        svc_node.setForeground(0, QColor("grey"))
        for svc in host.services:
            svc_item = QTreeWidgetItem(
                [svc.instance_name or svc.service_type, f"{svc.service_type} :{svc.port}"]
            )
            for k, v in svc.txt.items():
                svc_item.addChild(QTreeWidgetItem([k, str(v)]))
            svc_node.addChild(svc_item)
        top.addChild(svc_node)

        top.setExpanded(True)
        self._tree.resizeColumnToContents(0)

    def handle_results_removed(self, keys: list[str]) -> None:
        for key in keys:
            item = self._items.pop(key, None)
            if item is not None:
                self._tree.takeTopLevelItem(self._tree.indexOfTopLevelItem(item))


# ─── Scanner widgets ──────────────────────────────────────────────────────────

class ScannerWidget(QWidget):
    """
    Card widget for one scanner: header (name + interfaces dropdown + stop button)
    above a results view. Subclass and override _create_results_widget() to
    customise the results display.
    """

    def __init__(
        self,
        name: str,
        available: list[str],
        active: list[str],
        worker: DiscoveryWorker,
    ) -> None:
        super().__init__()
        self._name = name
        self._worker = worker
        self._iface_actions: dict[str, QAction] = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(4, 4, 4, 4)
        outer.setSpacing(4)

        # ── Header row ──────────────────────────────────────────────
        header = QHBoxLayout()

        label = QLabel(f"<b>{name}</b>")
        header.addWidget(label)

        self._iface_menu = _InterfaceMenu()
        self._iface_btn = QToolButton()
        self._iface_btn.setText("Interfaces ▾")
        self._iface_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._iface_btn.setMenu(self._iface_menu)
        header.addWidget(self._iface_btn)

        stop_btn = QPushButton("Stop")
        stop_btn.setFixedWidth(60)
        stop_btn.clicked.connect(lambda: worker.stop_scanner(name))
        header.addWidget(stop_btn)

        header.addStretch()
        outer.addLayout(header)

        # ── Divider ─────────────────────────────────────────────────
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        outer.addWidget(line)

        # ── Results ─────────────────────────────────────────────────
        self._results = self._create_results_widget()
        outer.addWidget(self._results)

        self.handle_interfaces_updated(available, active)

    def _create_results_widget(self) -> ScannerResultsWidget:
        return GenericResultsWidget()

    def handle_results_updated(self, key: str, result: dict) -> None:
        self._results.handle_results_updated(key, result)

    def handle_results_removed(self, keys: list[str]) -> None:
        self._results.handle_results_removed(keys)

    def handle_interfaces_updated(self, available: list[str], active: list[str]) -> None:
        active_set = set(active)

        # Add new interfaces
        for iface in available:
            if iface not in self._iface_actions:
                action = QAction(iface)
                action.setCheckable(True)
                action.triggered.connect(self._on_interface_toggled)
                self._iface_menu.addAction(action)
                self._iface_actions[iface] = action

        # Remove gone interfaces
        for iface in list(self._iface_actions):
            if iface not in available:
                self._iface_menu.removeAction(self._iface_actions.pop(iface))

        # Sync checked state without triggering the worker
        for iface, action in self._iface_actions.items():
            action.blockSignals(True)
            action.setChecked(iface in active_set)
            action.blockSignals(False)

    def _on_interface_toggled(self) -> None:
        active = [iface for iface, action in self._iface_actions.items() if action.isChecked()]
        self._worker.set_scanner_interfaces(self._name, active)


class MDNSScannerWidget(ScannerWidget):
    """ScannerWidget with an MDNSResultsWidget for rich host/service display."""

    def _create_results_widget(self) -> ScannerResultsWidget:
        return MDNSResultsWidget()


# ─── Main window ──────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    """Scrollable window containing one ScannerWidget per active scanner."""

    def __init__(self, worker: DiscoveryWorker) -> None:
        super().__init__()
        self._worker = worker
        self.setWindowTitle("Discovery")
        self.setMinimumSize(600, 400)

        self._builtin_scanners: list[str] = []

        file_menu = self.menuBar().addMenu("File")
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self._on_exit)
        file_menu.addAction(exit_action)

        self._scanners_menu = self.menuBar().addMenu("Scanners")

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self.setCentralWidget(scroll)

        container = QWidget()
        self._layout = QVBoxLayout(container)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._layout.addStretch()
        scroll.setWidget(container)

        self._scanner_widgets: dict[str, ScannerWidget] = {}

    def closeEvent(self, event) -> None:
        event.ignore()
        self.hide()

    def _on_exit(self) -> None:
        self._worker.requestInterruption()
        self._worker.wait()
        QApplication.quit()

    @pyqtSlot(list)
    def on_builtin_scanners_known(self, builtins: list) -> None:
        self._builtin_scanners = list(builtins)
        self._rebuild_scanners_menu()

    @pyqtSlot(str, list, list)
    def on_scanner_added(self, name: str, available: list, active: list) -> None:
        if name in self._scanner_widgets:
            return
        cls = MDNSScannerWidget if name == "mdns.v1" else ScannerWidget
        widget = cls(name, available, active, self._worker)
        # Insert before the trailing stretch
        self._layout.insertWidget(self._layout.count() - 1, widget)
        self._scanner_widgets[name] = widget
        self._rebuild_scanners_menu()

    @pyqtSlot(str)
    def on_scanner_removed(self, name: str) -> None:
        widget = self._scanner_widgets.pop(name, None)
        if widget is not None:
            self._layout.removeWidget(widget)
            widget.deleteLater()
        self._rebuild_scanners_menu()

    def _rebuild_scanners_menu(self) -> None:
        self._scanners_menu.clear()
        startable = [b for b in self._builtin_scanners if b not in self._scanner_widgets]
        if startable:
            for name in startable:
                action = QAction(f"Start {name}", self)
                action.triggered.connect(lambda checked, n=name: self._worker.start_builtin_scanner(n))
                self._scanners_menu.addAction(action)
        else:
            self._scanners_menu.addAction("(all scanners running)").setEnabled(False)

    @pyqtSlot(str, str, object)
    def on_results_updated(self, scanner: str, key: str, result) -> None:
        widget = self._scanner_widgets.get(scanner)
        if widget is not None:
            widget.handle_results_updated(key, result)

    @pyqtSlot(str, list)
    def on_results_removed(self, scanner: str, keys: list) -> None:
        widget = self._scanner_widgets.get(scanner)
        if widget is not None:
            widget.handle_results_removed(keys)

    @pyqtSlot(str, list, list)
    def on_interfaces_updated(self, scanner: str, available: list, active: list) -> None:
        widget = self._scanner_widgets.get(scanner)
        if widget is not None:
            widget.handle_interfaces_updated(available, active)


# ─── Tray icon ────────────────────────────────────────────────────────────────

class DiscoveryApplet(QSystemTrayIcon):
    """System tray icon; left-click toggles the main window."""

    def __init__(self) -> None:
        icon = QIcon.fromTheme("network-wired")
        if icon.isNull():
            icon = _fallback_icon()
        super().__init__(icon)

        self.worker = DiscoveryWorker()
        self._window = MainWindow(worker=self.worker)

        self.worker.status_changed.connect(self._on_status_changed)
        self.worker.builtin_scanners_known.connect(self._window.on_builtin_scanners_known)
        self.worker.scanner_added.connect(self._window.on_scanner_added)
        self.worker.scanner_removed.connect(self._window.on_scanner_removed)
        self.worker.results_updated.connect(self._window.on_results_updated)
        self.worker.results_removed.connect(self._window.on_results_removed)
        self.worker.interfaces_updated.connect(self._window.on_interfaces_updated)

        self.worker.start()
        self.activated.connect(self._on_activated)
        self.setToolTip("Discovery")

    @pyqtSlot(QSystemTrayIcon.ActivationReason)
    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self._window.isVisible():
                self._window.hide()
            else:
                self._window.show()
                self._window.raise_()
                self._window.activateWindow()

    def _on_status_changed(self, status: str) -> None:
        logger.info("Discovery status: %s", status)
        self.setToolTip(f"Discovery — {status}")
