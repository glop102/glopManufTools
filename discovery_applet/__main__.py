import sys

from PyQt6.QtWidgets import QApplication

from discovery_applet.applet import DiscoveryApplet


def main() -> None:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    applet = DiscoveryApplet()
    applet.show()

    worker = applet.worker
    app.aboutToQuit.connect(lambda: (worker.requestInterruption(), worker.wait()))

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
