"""
Minimal askpass helper for sudo -A.
Reads the prompt from argv[1], shows a GUI password dialog, prints the
password to stdout, and exits. A non-zero exit or empty output causes sudo
to abort the elevation.
"""
import sys
import tkinter as tk
import tkinter.simpledialog


def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else "Password:"

    root = tk.Tk()
    root.withdraw()  # Hide the root window, only show the dialog

    password = tkinter.simpledialog.askstring(
        title="Authentication Required",
        prompt=prompt,
        show="*",
        parent=root,
    )

    root.destroy()

    if password is None:
        # User cancelled
        sys.exit(1)

    print(password)


if __name__ == "__main__":
    main()
