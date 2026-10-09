# --- Standard Colors (Google Material Baseline) ---
COLOR_DARKRED = "\033[38;2;217;48;37m"       # Material Red 600
COLOR_DARKYELLOW = "\033[38;2;249;171;0m"    # Material Yellow 600
COLOR_YELLOW = "\033[38;2;253;214;99m"
COLOR_RED = "\033[38;2;242;139;130m"        # Material Red 300
COLOR_BLUE = "\033[38;2;138;180;248m"       # Material Blue 300
COLOR_GRAY = "\033[38;2;128;134;139m"       # Material Grey 500
COLOR_RESET = "\033[0m"

from datetime import datetime as dt

def info(msg):
    print(f"{COLOR_BLUE}[DEBUG ~ {dt.now().strftime('%H:%M:%S')}] {COLOR_RESET}{msg}")
def warn(msg):
    print(f"{COLOR_DARKYELLOW}[WARN ~ {dt.now().strftime('%H:%M:%S')}] {COLOR_YELLOW}{msg}{COLOR_RESET}")
def error(msg):
    print(f"{COLOR_DARKRED}[ERROR ~ {dt.now().strftime('%H:%M:%S')}] {COLOR_RED}{msg}{COLOR_RESET}")

