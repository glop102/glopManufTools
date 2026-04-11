"""
DiscoveryApplet — system tray icon that shows discovered mDNS hosts in a popup.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt, QPoint, pyqtSlot
from PyQt6.QtGui import QColor, QFont, QIcon, QPixmap, QCursor
from PyQt6.QtWidgets import (
    QApplication,
    QHeaderView,
    QPushButton,
    QScrollArea,
    QSystemTrayIcon,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    QLabel,
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


class ContextMenu(QWidget):
    """
    A frameless tool window that acts as a right-click context menu.

    Using QMenu on Wayland causes "Failed to create grabbing popup" errors
    because QMenu creates an xdg_popup surface which requires an input serial
    from a recent user event. A plain QWidget tool window (xdg_toplevel) has
    no such restriction.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint)
        self.setObjectName("ContextMenu")
        self.setStyleSheet("""
            #ContextMenu { background: palette(window); border: 1px solid palette(mid); }
            QPushButton { text-align: left; padding: 6px 16px; border: none; background: transparent; }
            QPushButton:hover { background: palette(highlight); color: palette(highlighted-text); }
        """)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

    def add_action(self, label: str, callback) -> None:
        btn = QPushButton(label)
        btn.clicked.connect(callback)
        btn.clicked.connect(self.hide)
        self._layout.addWidget(btn)

    def popup(self, pos: QPoint) -> None:
        self.adjustSize()
        self.move(pos)
        self.show()
        self.raise_()
        self.activateWindow()

    def focusOutEvent(self, event):
        focused = QApplication.focusWidget()
        if focused is None or not self.isAncestorOf(focused):
            self.hide()
        super().focusOutEvent(event)

    def changeEvent(self, event):
        from PyQt6.QtCore import QEvent
        if event.type() == QEvent.Type.ActivationChange and not self.isActiveWindow():
            self.hide()
        super().changeEvent(event)


class HostPopup(QWidget):
    """
    Frameless tool window that lists discovered hosts in a tree.

    Hides itself on focus loss so it behaves like a dropdown.
    """

    _FIXED_WIDTH = 380
    _MAX_HEIGHT = 500

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, False)
        self.setFixedWidth(self._FIXED_WIDTH)

        layout = QVBoxLayout(self)
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

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def refresh(self, hosts: dict[str, dict]) -> None:
        """Rebuild the tree from the current hosts dict."""
        self._tree.clear()

        if not hosts:
            self._tree.hide()
            self._placeholder.show()
            self.setFixedHeight(60)
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
        self._adjust_height()

    def _adjust_height(self) -> None:
        self._tree.resizeColumnToContents(0)
        # Estimate height from item count
        item_height = self._tree.sizeHintForRow(0) or 22
        total_items = self._tree.topLevelItemCount()
        # Count all visible rows roughly
        count = sum(
            1 + self._tree.topLevelItem(i).childCount()
            for i in range(total_items)
        )
        header_h = self._tree.header().height()
        desired = header_h + count * item_height + 8
        self.setFixedHeight(min(desired, self._MAX_HEIGHT))

    # ------------------------------------------------------------------
    # Focus-loss → auto-hide
    # ------------------------------------------------------------------

    def focusOutEvent(self, event):
        # Only hide if focus moved outside this widget hierarchy
        focused = QApplication.focusWidget()
        if focused is None or not self.isAncestorOf(focused):
            self.hide()
        super().focusOutEvent(event)

    def changeEvent(self, event):
        from PyQt6.QtCore import QEvent
        if event.type() == QEvent.Type.ActivationChange and not self.isActiveWindow():
            self.hide()
        super().changeEvent(event)


class DiscoveryApplet(QSystemTrayIcon):
    """System tray icon; left-click toggles the HostPopup."""

    def __init__(self) -> None:
        icon = QIcon.fromTheme("network-wired")
        if icon.isNull():
            icon = _fallback_icon()
        super().__init__(icon)

        self._hosts: dict[str, dict] = {}
        self._popup = HostPopup()

        self.activated.connect(self._on_activated)
        self._update_tooltip()

        # Context menu (right-click)
        # ContextMenu is a plain QWidget tool window instead of QMenu to avoid
        # the Wayland xdg_popup serial requirement that causes "Failed to create
        # grabbing popup" on compositors like Sway.
        self._menu = ContextMenu()
        self._menu.add_action("Start mdns.v1 scanner", self._on_start_mdns_scanner)
        self._menu.add_action("Stop all scanners", self._on_stop_all_scanners)

        # Worker thread
        self.worker = DiscoveryWorker()
        self.worker.hosts_updated.connect(self._on_host_updated)
        self.worker.hosts_removed.connect(self._on_hosts_removed)
        self.worker.status_changed.connect(self._on_status_changed)
        self.worker.start()

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @pyqtSlot(QSystemTrayIcon.ActivationReason)
    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self._popup.isVisible():
                self._popup.hide()
            else:
                self._show_popup()
        elif reason == QSystemTrayIcon.ActivationReason.Context:
            self._popup.hide()
            self._menu.popup(QCursor.pos())

    def _on_host_updated(self, key: str, host: dict) -> None:
        self._hosts[key] = host
        self._update_tooltip()
        if self._popup.isVisible():
            self._popup.refresh(self._hosts)

    def _on_hosts_removed(self, keys: list) -> None:
        for key in keys:
            self._hosts.pop(key, None)
        self._update_tooltip()
        if self._popup.isVisible():
            self._popup.refresh(self._hosts)

    def _on_status_changed(self, status: str) -> None:
        logger.info("Discovery status: %s", status)
        self.setToolTip(f"Discovery — {status}")

    def _on_start_mdns_scanner(self) -> None:
        logger.info("Requesting start of mdns.v1 scanner")
        self.worker.start_mdns_scanner()

    def _on_stop_all_scanners(self) -> None:
        logger.info("Requesting stop for all scanners")
        self.worker.stop_all_scanners()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_tooltip(self) -> None:
        n = len(self._hosts)
        self.setToolTip(f"{n} host{'s' if n != 1 else ''} discovered")

    def _show_popup(self) -> None:
        self._popup.refresh(self._hosts)

        # Position near the tray icon; fall back to cursor position
        geo = self.geometry()
        if geo.isNull():
            pos: QPoint = QCursor.pos()
        else:
            pos = geo.topLeft()

        screen = self._popup.screen() or self._popup.windowHandle()
        if screen:
            from PyQt6.QtGui import QScreen
            if isinstance(screen, QScreen):
                screen_geo = screen.availableGeometry()
                # Push popup above taskbar if icon is at the bottom
                if pos.y() + self._popup.height() > screen_geo.bottom():
                    pos.setY(pos.y() - self._popup.height())
                # Keep within screen bounds horizontally
                if pos.x() + self._popup.width() > screen_geo.right():
                    pos.setX(screen_geo.right() - self._popup.width())

        self._popup.move(pos)
        self._popup.show()
        self._popup.raise_()
        self._popup.activateWindow()
