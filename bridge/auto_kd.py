import subprocess
import threading
import sys
import time

KD_PATH = r"D:\WinDDK\7600.16385.1\Debuggers\kd.exe"
ARGS = [KD_PATH, "-k", r"com:pipe,port=\\.\pipe\KdNet,reconnect", "-g"]

print("[*] Starting kd.exe with auto-feeder...")
proc = subprocess.Popen(
    ARGS,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

def reader():
    while proc.poll() is None:
        try:
            chunk = proc.stdout.read(1)
            if not chunk:
                break
            print(chunk, end='', flush=True)
        except Exception:
            break

t_read = threading.Thread(target=reader, daemon=True)
t_read.start()

def feeder():
    time.sleep(1)
    # Send initial configuration commands
    initial_cmds = [
        "sxd ld\n",
        "sxd ib\n",
        "sxd *\n",
        "g\n"
    ]
    for cmd in initial_cmds:
        try:
            proc.stdin.write(cmd)
            proc.stdin.flush()
            time.sleep(0.3)
        except Exception:
            return

    # Continuous go pulse every 1 second
    while proc.poll() is None:
        try:
            proc.stdin.write("g\n")
            proc.stdin.flush()
        except Exception:
            break
        time.sleep(1)

t_feed = threading.Thread(target=feeder, daemon=True)
t_feed.start()

try:
    proc.wait()
except KeyboardInterrupt:
    proc.terminate()

