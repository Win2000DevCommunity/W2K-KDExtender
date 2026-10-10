"""
kdbridge_gui.py -- Graphical KD Network Bridge for VirtualBox

Provides a full graphical user interface (Tkinter) for monitoring and controlling
kernel debugging traffic between VirtualBox and WinDbg / kd.exe.

Features:
  - Live statistics: RX frames, TX frames, byte counters, learned MAC address.
  - Pipe status & UDP tunnel status indicators.
  - Interactive Action Buttons:
      * Break Target ('b') -- Injects remote break byte to halt VM into debugger
      * Resume / Go ('g')  -- Sends go signal to resume target execution
      * Reset VM           -- Reboots the VirtualBox VM via VBoxManage
      * Launch WinDbg      -- Launches GUI WinDbg attached to \\\\.\\pipe\\KdNet
      * Launch kd.exe      -- Launches WinDDK console debugger
      * Auto-Go Toggle     -- Automatically pulses 'g' every 1s during boot
  - Real-time scrolling packet & event log.
"""

import sys
import os
import socket
import struct
import threading
import time
import queue
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# --- Constants ---
KD_ETHERTYPE_BE = 0x88B5
ETHER_HDR_SIZE  = 16
MAX_PAYLOAD     = 1500
BROADCAST_MAC   = b'\xFF\xFF\xFF\xFF\xFF\xFF'
HOST_MAC        = b'\x00\x50\x56\xC0\x00\x01'
DEFAULT_VBOX_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
DEFAULT_VM_NAME   = "win2000AHCI"

# Windows Named Pipe constants
if sys.platform == 'win32':
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32
    PIPE_ACCESS_DUPLEX   = 0x00000003
    PIPE_TYPE_BYTE       = 0x00000000
    PIPE_READMODE_BYTE   = 0x00000000
    PIPE_WAIT            = 0x00000000
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


class KdBridgeEngine:
    def __init__(self, log_queue, stat_queue):
        self.log_queue = log_queue
        self.stat_queue = stat_queue
        self.sport = 40000
        self.dport = 40001
        self.host = '127.0.0.1'
        self.pipe_name = r'\\.\pipe\KdNet'
        
        self.target_mac = bytes.fromhex('0800275AA667')
        self.target_mac_lock = threading.Lock()
        
        self.running = False
        self.pipe_connected = threading.Event()
        self.pipe_handle = None
        self.pipe_rx_buffer = bytearray()
        self.udp_sock = None
        self.vbox_addr = (self.host, self.sport)
        
        self.rx_frames = 0
        self.tx_frames = 0
        self.rx_bytes = 0
        self.tx_bytes = 0
        
        self.auto_go_enabled = False
        self.feeder_proc = None

    def log(self, text, tag="info"):
        self.log_queue.put((time.strftime("%H:%M:%S"), text, tag))

    def update_stats(self):
        with self.target_mac_lock:
            mac_str = ':'.join(f'{b:02X}' for b in self.target_mac) if self.target_mac else "Unknown"
        self.stat_queue.put({
            'rx_frames': self.rx_frames,
            'tx_frames': self.tx_frames,
            'rx_bytes': self.rx_bytes,
            'tx_bytes': self.tx_bytes,
            'mac': mac_str,
            'connected': self.pipe_connected.is_set()
        })

    def build_kd_frame(self, data):
        with self.target_mac_lock:
            dst = self.target_mac if self.target_mac else BROADCAST_MAC
        if len(data) > MAX_PAYLOAD:
            return None
        frame = bytearray()
        frame += dst
        frame += HOST_MAC
        frame += struct.pack('>H', KD_ETHERTYPE_BE)
        frame += struct.pack('<H', len(data))
        frame += data
        if len(frame) < 60:
            frame += b'\x00' * (60 - len(frame))
        return bytes(frame)

    def parse_kd_frame(self, raw):
        if len(raw) < ETHER_HDR_SIZE:
            return None
        ethertype = struct.unpack('>H', raw[12:14])[0]
        if ethertype != KD_ETHERTYPE_BE:
            return None
        with self.target_mac_lock:
            if self.target_mac is None:
                self.target_mac = raw[6:12]
                self.log(f"Learned target MAC: {':'.join(f'{b:02X}' for b in self.target_mac)}", "sys")
        payload_len = struct.unpack('<H', raw[14:16])[0]
        if payload_len <= 0 or payload_len > MAX_PAYLOAD:
            return None
        if len(raw) < ETHER_HDR_SIZE + payload_len:
            return None
        return raw[ETHER_HDR_SIZE : ETHER_HDR_SIZE + payload_len]

    def create_named_pipe(self):
        h = kernel32.CreateNamedPipeW(
            self.pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 65536, 65536, 0, None
        )
        if h == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error() or kernel32.GetLastError()
            raise OSError(f"CreateNamedPipe failed: error {err}")
        return h

    def wait_pipe_connection(self):
        self.log(f"Waiting for Debugger to connect on {self.pipe_name}...", "sys")
        ok = kernel32.ConnectNamedPipe(self.pipe_handle, None)
        if not ok:
            err = kernel32.GetLastError()
            if err != 535:  # ERROR_PIPE_CONNECTED
                raise OSError(f"ConnectNamedPipe error {err}")
        self.log("Debugger connected to named pipe!", "success")
        self.pipe_connected.set()

    def pipe_read_raw(self, size):
        avail = wintypes.DWORD(0)
        if not kernel32.PeekNamedPipe(self.pipe_handle, None, 0, None, ctypes.byref(avail), None):
            err = kernel32.GetLastError()
            if err in (109, 233):
                return None
            return b''
        if avail.value == 0:
            return b''
        to_read = min(size, avail.value)
        buf = ctypes.create_string_buffer(to_read)
        read = wintypes.DWORD(0)
        ok = kernel32.ReadFile(self.pipe_handle, buf, to_read, ctypes.byref(read), None)
        if not ok or read.value == 0:
            err = kernel32.GetLastError()
            if err in (109, 233):
                return None
            return b''
        return buf.raw[:read.value]

    def pull_available(self):
        avail = wintypes.DWORD(0)
        if kernel32.PeekNamedPipe(self.pipe_handle, None, 0, None, ctypes.byref(avail), None):
            if avail.value > 0:
                more = self.pipe_read_raw(min(avail.value, 4096))
                if more is None:
                    return False
                if more:
                    self.pipe_rx_buffer.extend(more)
        else:
            err = kernel32.GetLastError()
            if err in (109, 233):
                return False
        return True

    def pipe_read_kd_message(self):
        if not self.pipe_rx_buffer:
            data = self.pipe_read_raw(4096)
            if data is None:
                return None
            if not data:
                time.sleep(0.002)
                return b''
            self.pipe_rx_buffer.extend(data)

        if not self.pull_available():
            return None

        KD_LEADERS = (b'0000', b'iiii', b'ssss')
        if self.pipe_rx_buffer.startswith(b'b') and (len(self.pipe_rx_buffer) == 1 or bytes(self.pipe_rx_buffer[1:5]) not in KD_LEADERS):
            res = bytes(self.pipe_rx_buffer[:1])
            del self.pipe_rx_buffer[:1]
            return res

        def is_leader_prefix(buf):
            for leader in KD_LEADERS:
                if leader.startswith(bytes(buf[:min(len(buf), 4)])):
                    return True
            return False

        if len(self.pipe_rx_buffer) < 4 and is_leader_prefix(self.pipe_rx_buffer):
            start_t = time.perf_counter()
            while len(self.pipe_rx_buffer) < 4 and (time.perf_counter() - start_t) < 0.05:
                if not self.pull_available():
                    return None
                if len(self.pipe_rx_buffer) < 4:
                    time.sleep(0.001)

        if len(self.pipe_rx_buffer) >= 4:
            leader = bytes(self.pipe_rx_buffer[:4])
            start_t = time.perf_counter()
            if leader == b'iiii':
                while len(self.pipe_rx_buffer) < 16 and (time.perf_counter() - start_t) < 0.15:
                    if not self.pull_available():
                        return None
                    if len(self.pipe_rx_buffer) < 16:
                        time.sleep(0.001)
                if len(self.pipe_rx_buffer) >= 16:
                    res = bytes(self.pipe_rx_buffer[:16])
                    del self.pipe_rx_buffer[:16]
                    return res
            elif leader in (b'0000', b'ssss'):
                while len(self.pipe_rx_buffer) < 8 and (time.perf_counter() - start_t) < 0.10:
                    if not self.pull_available():
                        return None
                    if len(self.pipe_rx_buffer) < 8:
                        time.sleep(0.001)
                if len(self.pipe_rx_buffer) >= 8:
                    payload_len = struct.unpack('<H', self.pipe_rx_buffer[6:8])[0]
                    total_len = 16 + payload_len + 1
                    while len(self.pipe_rx_buffer) < total_len and (time.perf_counter() - start_t) < 0.25:
                        if not self.pull_available():
                            return None
                        if len(self.pipe_rx_buffer) < total_len:
                            time.sleep(0.001)
                    if len(self.pipe_rx_buffer) >= total_len:
                        res = bytes(self.pipe_rx_buffer[:total_len])
                        del self.pipe_rx_buffer[:total_len]
                        return res

        start_t = time.perf_counter()
        while (time.perf_counter() - start_t) < 0.003:
            if not self.pull_available():
                return None
            time.sleep(0.0005)

        chunk_size = min(len(self.pipe_rx_buffer), MAX_PAYLOAD)
        res = bytes(self.pipe_rx_buffer[:chunk_size])
        del self.pipe_rx_buffer[:chunk_size]
        return res

    def pipe_write(self, data):
        written = wintypes.DWORD(0)
        ok = kernel32.WriteFile(self.pipe_handle, data, len(data), ctypes.byref(written), None)
        return ok and (written.value > 0)

    def start(self):
        self.running = True
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_sock.bind(('0.0.0.0', self.dport))
        self.log(f"UDP Tunnel bound to port {self.dport} (sending to {self.host}:{self.sport})", "sys")

        self.pipe_handle = self.create_named_pipe()
        threading.Thread(target=self._connection_watcher_thread, daemon=True).start()
        threading.Thread(target=self._udp_to_pipe_loop, daemon=True).start()
        threading.Thread(target=self._pipe_to_udp_loop, daemon=True).start()
        threading.Thread(target=self._control_loop, daemon=True).start()
        threading.Thread(target=self._auto_go_loop, daemon=True).start()

    def _connection_watcher_thread(self):
        while self.running:
            try:
                self.wait_pipe_connection()
                while self.pipe_connected.is_set() and self.running:
                    time.sleep(0.5)
            except Exception as e:
                self.log(f"Pipe error: {e}", "err")
                time.sleep(1)

    def _udp_to_pipe_loop(self):
        while self.running:
            try:
                data, _ = self.udp_sock.recvfrom(65536)
            except OSError:
                break
            payload = self.parse_kd_frame(data)
            if payload is None:
                continue
            self.rx_frames += 1
            self.rx_bytes += len(payload)
            if self.rx_frames <= 100 or self.rx_frames % 20 == 0 or len(payload) == 1:
                leader = payload[:4]
                extra = ''
                if leader == b'iiii' and len(payload) >= 6:
                    ptype = struct.unpack('<H', payload[4:6])[0]
                    names = {4: 'ACK', 5: 'RESEND', 6: 'RESET'}
                    extra = f" [{names.get(ptype, f'Type {ptype}')}]"
                elif leader in (b'0000', b'ssss') and len(payload) >= 6:
                    ptype = struct.unpack('<H', payload[4:6])[0]
                    names = {2: 'STATE_CHANGE32', 3: 'STATE_MANIPULATE', 7: 'IO'}
                    extra = f" [{names.get(ptype, f'Type {ptype}')}]"
                self.log(f"[>] VM Frame #{self.rx_frames} ({len(payload)}B): {payload[:16].hex()}{extra}", "rx")
            
            if self.pipe_connected.is_set():
                self.pipe_write(payload)
            self.update_stats()

    def _pipe_to_udp_loop(self):
        while self.running:
            if not self.pipe_connected.is_set():
                time.sleep(0.1)
                continue
            data = self.pipe_read_kd_message()
            if data is None:
                self.log("Debugger disconnected from pipe. Re-opening listener...", "warn")
                self.pipe_connected.clear()
                self.pipe_rx_buffer = bytearray()
                kernel32.DisconnectNamedPipe(self.pipe_handle)
                continue
            if not data:
                continue
            frame = self.build_kd_frame(data)
            if frame is None:
                continue
            self.tx_frames += 1
            self.tx_bytes += len(data)
            if self.tx_frames <= 100 or self.tx_frames % 20 == 0 or len(data) == 1:
                extra = " [BREAK-IN 'b']" if data == b'b' else ""
                self.log(f"[<] WinDbg Frame #{self.tx_frames} ({len(data)}B): {data[:16].hex()}{extra}", "tx")
            self.udp_sock.sendto(frame, self.vbox_addr)
            self.update_stats()

    def _control_loop(self):
        cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            cmd_sock.bind(('127.0.0.1', 40002))
        except OSError:
            return
        while self.running:
            try:
                data, _ = cmd_sock.recvfrom(1024)
                cmd = data.strip().lower()
                if cmd in (b'break', b'b'):
                    self.send_break()
                elif cmd == b'reset':
                    self.send_reset_packet()
            except Exception:
                time.sleep(0.1)

    def _auto_go_loop(self):
        while self.running:
            if self.auto_go_enabled and self.pipe_connected.is_set():
                # Emit periodic go signal if enabled
                time.sleep(1.0)
                if self.auto_go_enabled and self.pipe_connected.is_set():
                    self.send_go()
            else:
                time.sleep(0.5)

    def send_break(self):
        frame = self.build_kd_frame(b'b')
        if frame and self.udp_sock:
            self.udp_sock.sendto(frame, self.vbox_addr)
            self.log("[Control] Injected Break-In byte ('b') into VM network stream!", "action")

    def send_reset_packet(self):
        reset_pkt = b'iiii\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        frame = self.build_kd_frame(reset_pkt)
        if frame and self.udp_sock:
            self.udp_sock.sendto(frame, self.vbox_addr)
            self.log("[Control] Injected KD RESET packet to VM!", "action")

    def send_go(self):
        if self.pipe_connected.is_set():
            # In WinDbg pipe stream, 'g\n' resumes target if waiting for prompt
            try:
                self.pipe_write(b"g\n")
                self.log("[Control] Injected 'g' (Go) pulse to debugger pipe", "action")
            except Exception as e:
                self.log(f"Send go error: {e}", "err")

    def reset_vm(self, vm_name=DEFAULT_VM_NAME):
        def _task():
            self.log(f"Sending hardware reset to VirtualBox VM '{vm_name}'...", "warn")
            try:
                res = subprocess.run(
                    [DEFAULT_VBOX_PATH, "controlvm", vm_name, "reset"],
                    capture_output=True, text=True, timeout=10
                )
                if res.returncode == 0:
                    self.log(f"VM '{vm_name}' reset successfully!", "success")
                else:
                    self.log(f"VBoxManage reset failed: {res.stderr.strip()}", "err")
            except Exception as e:
                self.log(f"Failed to reset VM: {e}", "err")
        threading.Thread(target=_task, daemon=True).start()


class KdBridgeGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("KDTransport — Network Kernel Debugger Bridge (VirtualBox)")
        self.geometry("820x650")
        self.minsize(700, 500)

        # Apply clean dark/slate theme
        self.configure(bg="#1e1e2e")
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self._configure_styles()

        self.log_queue = queue.Queue()
        self.stat_queue = queue.Queue()
        self.engine = KdBridgeEngine(self.log_queue, self.stat_queue)

        self._build_ui()
        self.engine.start()
        self._process_queues()

    def _configure_styles(self):
        self.style.configure(".", background="#1e1e2e", foreground="#cdd6f4", font=("Segoe UI", 10))
        self.style.configure("TLabel", background="#1e1e2e", foreground="#cdd6f4")
        self.style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#89b4fa")
        self.style.configure("Card.TFrame", background="#2a2b3d", relief="flat")
        self.style.configure("BadgeGreen.TLabel", background="#a6e3a1", foreground="#11111b", font=("Segoe UI", 9, "bold"))
        self.style.configure("BadgeRed.TLabel", background="#f38ba8", foreground="#11111b", font=("Segoe UI", 9, "bold"))
        self.style.configure("StatVal.TLabel", font=("Segoe UI", 13, "bold"), foreground="#fab387", background="#2a2b3d")
        self.style.configure("StatTitle.TLabel", font=("Segoe UI", 9), foreground="#a6adc8", background="#2a2b3d")

    def _build_ui(self):
        # Top banner
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=15, pady=(15, 10))
        
        lbl_title = ttk.Label(top_frame, text="⚡ KDTransport Network Bridge", style="Header.TLabel")
        lbl_title.pack(side="left")

        self.lbl_pipe_status = tk.Label(top_frame, text="PIPE: WAITING", bg="#f38ba8", fg="#11111b", font=("Segoe UI", 9, "bold"), padx=8, pady=3, relief="flat")
        self.lbl_pipe_status.pack(side="right", padx=5)

        self.lbl_udp_status = tk.Label(top_frame, text="UDP :40001 ACTIVE", bg="#a6e3a1", fg="#11111b", font=("Segoe UI", 9, "bold"), padx=8, pady=3, relief="flat")
        self.lbl_udp_status.pack(side="right", padx=5)

        # Statistics Card
        stats_card = ttk.Frame(self, style="Card.TFrame")
        stats_card.pack(fill="x", padx=15, pady=5)

        # 4 Stat columns
        col1 = ttk.Frame(stats_card, style="Card.TFrame")
        col1.pack(side="left", expand=True, fill="both", padx=10, pady=10)
        ttk.Label(col1, text="RX Frames (VM -> Host)", style="StatTitle.TLabel").pack()
        self.val_rx = ttk.Label(col1, text="0", style="StatVal.TLabel")
        self.val_rx.pack()

        col2 = ttk.Frame(stats_card, style="Card.TFrame")
        col2.pack(side="left", expand=True, fill="both", padx=10, pady=10)
        ttk.Label(col2, text="TX Frames (Host -> VM)", style="StatTitle.TLabel").pack()
        self.val_tx = ttk.Label(col2, text="0", style="StatVal.TLabel")
        self.val_tx.pack()

        col3 = ttk.Frame(stats_card, style="Card.TFrame")
        col3.pack(side="left", expand=True, fill="both", padx=10, pady=10)
        ttk.Label(col3, text="Total Transferred", style="StatTitle.TLabel").pack()
        self.val_bytes = ttk.Label(col3, text="0 KB", style="StatVal.TLabel")
        self.val_bytes.pack()

        col4 = ttk.Frame(stats_card, style="Card.TFrame")
        col4.pack(side="left", expand=True, fill="both", padx=10, pady=10)
        ttk.Label(col4, text="Target MAC", style="StatTitle.TLabel").pack()
        self.val_mac = ttk.Label(col4, text="08:00:27:5A:A6:67", style="StatVal.TLabel")
        self.val_mac.pack()

        # Action Toolbar Frame
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=15, pady=8)

        # Buttons
        btn_break = tk.Button(toolbar, text="🛑 Break Target (b)", bg="#e78284", fg="#11111b", font=("Segoe UI", 10, "bold"),
                              padx=10, pady=4, relief="flat", activebackground="#ea999c", cursor="hand2",
                              command=self._on_break_clicked)
        btn_break.pack(side="left", padx=4)

        btn_go = tk.Button(toolbar, text="▶️ Resume / Go (g)", bg="#a6e3a1", fg="#11111b", font=("Segoe UI", 10, "bold"),
                           padx=10, pady=4, relief="flat", activebackground="#94e2d5", cursor="hand2",
                           command=self._on_go_clicked)
        btn_go.pack(side="left", padx=4)

        btn_reset = tk.Button(toolbar, text="🔄 Reset VM", bg="#fab387", fg="#11111b", font=("Segoe UI", 10, "bold"),
                             padx=10, pady=4, relief="flat", activebackground="#f9e2af", cursor="hand2",
                             command=self._on_reset_vm_clicked)
        btn_reset.pack(side="left", padx=4)

        btn_windbg = tk.Button(toolbar, text="🐛 Launch WinDbg", bg="#89b4fa", fg="#11111b", font=("Segoe UI", 10, "bold"),
                               padx=10, pady=4, relief="flat", activebackground="#b4befe", cursor="hand2",
                               command=self._on_launch_windbg)
        btn_windbg.pack(side="left", padx=4)

        # Auto-Go checkbox
        self.auto_go_var = tk.BooleanVar(value=False)
        chk_autogo = tk.Checkbutton(toolbar, text="Auto 'g' Pulse (Boot Feeder)", variable=self.auto_go_var,
                                    bg="#1e1e2e", fg="#cdd6f4", selectcolor="#2a2b3d", activebackground="#1e1e2e",
                                    activeforeground="#cdd6f4", font=("Segoe UI", 9),
                                    command=self._on_autogo_toggled)
        chk_autogo.pack(side="right", padx=10)

        # Log Section
        log_label_frame = ttk.Frame(self)
        log_label_frame.pack(fill="x", padx=15, pady=(8, 2))
        ttk.Label(log_label_frame, text="Live KD Traffic & Event Console", font=("Segoe UI", 10, "bold")).pack(side="left")

        btn_clear = tk.Button(log_label_frame, text="Clear", bg="#313244", fg="#cdd6f4", font=("Segoe UI", 8),
                              padx=6, pady=1, relief="flat", command=self._on_clear_log)
        btn_clear.pack(side="right")

        self.log_text = scrolledtext.ScrolledText(
            self, wrap="word", bg="#11111b", fg="#cdd6f4", insertbackground="#cdd6f4",
            font=("Consolas", 9), relief="flat", padx=8, pady=8
        )
        self.log_text.pack(fill="both", expand=True, padx=15, pady=(2, 15))

        # Tag colors
        self.log_text.tag_config("time", foreground="#6c7086")
        self.log_text.tag_config("rx", foreground="#a6e3a1")
        self.log_text.tag_config("tx", foreground="#89b4fa")
        self.log_text.tag_direction = "bottom"
        self.log_text.tag_config("action", foreground="#fab387", font=("Consolas", 9, "bold"))
        self.log_text.tag_config("success", foreground="#a6e3a1", font=("Consolas", 9, "bold"))
        self.log_text.tag_config("warn", foreground="#f9e2af")
        self.log_text.tag_config("err", foreground="#f38ba8", font=("Consolas", 9, "bold"))
        self.log_text.tag_config("sys", foreground="#cba6f7")

    def _on_break_clicked(self):
        self.engine.send_break()

    def _on_go_clicked(self):
        self.engine.send_go()

    def _on_reset_vm_clicked(self):
        self.engine.reset_vm()

    def _on_autogo_toggled(self):
        self.engine.auto_go_enabled = self.auto_go_var.get()
        state = "ENABLED" if self.engine.auto_go_enabled else "DISABLED"
        self.engine.log(f"Auto-Go boot feeder {state}", "action")

    def _on_launch_windbg(self):
        def _launch():
            windbg_paths = [
                r"D:\WinDDK\7600.16385.1\Debuggers\windbg.exe",
                r"C:\Program Files (x86)\Debugging Tools for Windows (x86)\windbg.exe"
            ]
            path = next((p for p in windbg_paths if os.path.exists(p)), "windbg.exe")
            cmd = [path, "-k", r"com:pipe,port=\\.\pipe\KdNet,resets=0,reconnect"]
            self.engine.log(f"Launching WinDbg: {' '.join(cmd)}", "sys")
            try:
                subprocess.Popen(cmd)
            except Exception as e:
                self.engine.log(f"Failed to launch WinDbg: {e}", "err")
        threading.Thread(target=_launch, daemon=True).start()

    def _on_clear_log(self):
        self.log_text.delete("1.0", tk.END)

    def _process_queues(self):
        # Flush logs
        while not self.log_queue.empty():
            t_str, msg, tag = self.log_queue.get_nowait()
            self.log_text.insert(tk.END, f"[{t_str}] ", "time")
            self.log_text.insert(tk.END, f"{msg}\n", tag)
            self.log_text.see(tk.END)

        # Flush stats
        while not self.stat_queue.empty():
            st = self.stat_queue.get_nowait()
            self.val_rx.config(text=f"{st['rx_frames']:,}")
            self.val_tx.config(text=f"{st['tx_frames']:,}")
            total_kb = (st['rx_bytes'] + st['tx_bytes']) / 1024
            self.val_bytes.config(text=f"{total_kb:.1f} KB")
            self.val_mac.config(text=st['mac'])

            if st['connected']:
                self.lbl_pipe_status.config(text="PIPE: CONNECTED", bg="#a6e3a1")
            else:
                self.lbl_pipe_status.config(text="PIPE: WAITING", bg="#f38ba8")

        self.after(50, self._process_queues)


def main():
    app = KdBridgeGui()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
