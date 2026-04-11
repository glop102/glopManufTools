import signal
import sys

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from discovery_applet.applet import DiscoveryApplet


def main() -> None:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    signal.signal(signal.SIGINT, lambda *_: app.quit())
    # Qt blocks in C++ between events; this timer wakes Python regularly
    # so the signal handler above can actually fire.
    sigint_timer = QTimer()
    sigint_timer.setInterval(200)
    sigint_timer.timeout.connect(lambda: None)
    sigint_timer.start()

    applet = DiscoveryApplet()
    applet.show()

    worker = applet.worker
    app.aboutToQuit.connect(lambda: (worker.requestInterruption(), worker.wait()))

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
