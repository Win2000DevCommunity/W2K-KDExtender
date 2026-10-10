"""
kdbridge.py -- KD Network Bridge for VirtualBox (no Npcap needed)

Uses VirtualBox's built-in UDP Tunnel network mode to receive raw Ethernet
frames over UDP, filter for EtherType 0x88B5, and pipe the KD payload bytes
to WinDbg via a named pipe.

VirtualBox Setup:
  VM Settings -> Network -> Adapter 1:
    Attached to: "Generic Driver"
    Name:        "UDPTunnel"
  Then in Advanced or via command line:
    VBoxManage modifyvm "win2000AHCI" --nic1 generic
    VBoxManage modifyvm "win2000AHCI" --nicgenericdrv1 "UDPTunnel"
    VBoxManage modifyvm "win2000AHCI" --nicproperty1 "dest=127.0.0.1"
    VBoxManage modifyvm "win2000AHCI" --nicproperty1 "sport=40000"
    VBoxManage modifyvm "win2000AHCI" --nicproperty1 "dport=40001"

This script listens on UDP port 40001 (dport) for frames from VBox,
and sends responses back to UDP port 40000 (sport) where VBox listens.

Usage:
  python kdbridge.py
  Then: windbg -k com:pipe,port=\\\\.\\pipe\\KdNet,reconnect

Or with custom ports:
  python kdbridge.py --sport 40000 --dport 40001 --pipe \\\\.\\pipe\\KdNet
"""

import sys
import os
import socket
import struct
import threading
import time
import argparse

# --- Constants matching kdtransport_net.c ---
KD_ETHERTYPE_BE = 0x88B5       # big-endian on wire
ETHER_HDR_SIZE  = 16           # 6 dst + 6 src + 2 ethertype + 2 payload_len
MAX_PAYLOAD     = 1500

# Broadcast MAC
BROADCAST_MAC = b'\xFF\xFF\xFF\xFF\xFF\xFF'

# "Host" MAC -- arbitrary, target doesn't filter by dst MAC
HOST_MAC = b'\x00\x50\x56\xC0\x00\x01'

# Learned target MAC (default to VirtualBox MAC)
target_mac = bytes.fromhex('0800275AA667')
target_mac_lock = threading.Lock()


def build_kd_frame(data):
    """Wrap KD payload bytes into an Ethernet frame with EtherType 0x88B5."""
    global target_mac
    with target_mac_lock:
        dst = target_mac if target_mac else BROADCAST_MAC
    
    payload_len = len(data)
    if payload_len > MAX_PAYLOAD:
        return None
    
    frame = bytearray()
    frame += dst                                    # 6 bytes dst MAC
    frame += HOST_MAC                               # 6 bytes src MAC
    frame += struct.pack('>H', KD_ETHERTYPE_BE)     # 2 bytes EtherType (big-endian)
    frame += struct.pack('<H', payload_len)          # 2 bytes payload len (little-endian)
    frame += data                                   # payload
    
    # Pad to Ethernet minimum (60 bytes)
    if len(frame) < 60:
        frame += b'\x00' * (60 - len(frame))
    
    return bytes(frame)


def parse_kd_frame(raw):
    """Parse an Ethernet frame; return KD payload bytes or None."""
    global target_mac
    
    if len(raw) < ETHER_HDR_SIZE:
        return None
    
    # Check EtherType (bytes 12-13, big-endian)
    ethertype = struct.unpack('>H', raw[12:14])[0]
    if ethertype != KD_ETHERTYPE_BE:
        return None
    
    # Learn target MAC from source field
    with target_mac_lock:
        if target_mac is None:
            target_mac = raw[6:12]
            mac_str = ':'.join(f'{b:02X}' for b in target_mac)
            print(f'[*] Learned target MAC: {mac_str}')
    
    # Payload length (bytes 14-15, little-endian)
    payload_len = struct.unpack('<H', raw[14:16])[0]
    if payload_len <= 0 or payload_len > MAX_PAYLOAD:
        return None
    if len(raw) < ETHER_HDR_SIZE + payload_len:
        return None
    
    return raw[ETHER_HDR_SIZE : ETHER_HDR_SIZE + payload_len]


# --- Windows Named Pipe ---

if sys.platform == 'win32':
    import ctypes
    from ctypes import wintypes
    
    kernel32 = ctypes.windll.kernel32
    
    PIPE_ACCESS_DUPLEX    = 0x00000003
    PIPE_TYPE_BYTE        = 0x00000000
    PIPE_READMODE_BYTE    = 0x00000000
    PIPE_WAIT             = 0x00000000
    INVALID_HANDLE_VALUE  = wintypes.HANDLE(-1).value
    
    def create_named_pipe(pipe_name):
        """Create a Windows named pipe and wait for WinDbg to connect."""
        h = kernel32.CreateNamedPipeW(
            pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,       # max instances
            65536,   # out buffer
            65536,   # in buffer
            0,       # default timeout
            None     # security
        )
        if h == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error() or kernel32.GetLastError()
            raise OSError(f'CreateNamedPipe failed: error {err}')
        
        print(f'[*] Waiting for WinDbg to connect on {pipe_name} ...')
        ok = kernel32.ConnectNamedPipe(h, None)
        if not ok:
            err = kernel32.GetLastError()
            # ERROR_PIPE_CONNECTED = 535 means client already connected, that's OK
            if err != 535:
                raise OSError(f'ConnectNamedPipe failed: error {err}')
        
        print('[*] WinDbg connected!')
        return h
    
    pipe_rx_buffer = bytearray()

    def pipe_read_raw(handle, size):
        """Low-level non-blocking read from named pipe using PeekNamedPipe."""
        avail = wintypes.DWORD(0)
        if not kernel32.PeekNamedPipe(handle, None, 0, None, ctypes.byref(avail), None):
            err = kernel32.GetLastError()
            if err in (109, 233):  # ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED
                return None
            return b''
        
        if avail.value == 0:
            return b''
        
        to_read = min(size, avail.value)
        buf = ctypes.create_string_buffer(to_read)
        read = wintypes.DWORD(0)
        ok = kernel32.ReadFile(handle, buf, to_read, ctypes.byref(read), None)
        if not ok or read.value == 0:
            err = kernel32.GetLastError()
            if err in (109, 233):
                return None
            return b''
        return buf.raw[:read.value]

    def pull_available(handle):
        """Pull any currently pending bytes in the pipe into pipe_rx_buffer."""
        global pipe_rx_buffer
        avail = wintypes.DWORD(0)
        if kernel32.PeekNamedPipe(handle, None, 0, None, ctypes.byref(avail), None):
            if avail.value > 0:
                more = pipe_read_raw(handle, min(avail.value, 4096))
                if more is None:
                    return False
                if more:
                    pipe_rx_buffer.extend(more)
        else:
            err = kernel32.GetLastError()
            if err in (109, 233):
                return False
        return True

    def pipe_read_kd_message(handle):
        """Read a complete KD packet or coalesced message chunk from the named pipe."""
        global pipe_rx_buffer
        
        # 1. Ensure we have at least some data
        if not pipe_rx_buffer:
            data = pipe_read_raw(handle, 4096)
            if data is None:
                return None  # Disconnected
            if not data:
                time.sleep(0.002)
                return b''
            pipe_rx_buffer.extend(data)
        
        # Pull any extra bytes already queued
        if not pull_available(handle):
            return None
        
        KD_LEADERS = (b'0000', b'iiii', b'ssss')
        
        # Check if first byte is a break-in character 'b' (0x62)
        if pipe_rx_buffer.startswith(b'b') and (len(pipe_rx_buffer) == 1 or bytes(pipe_rx_buffer[1:5]) not in KD_LEADERS):
            res = bytes(pipe_rx_buffer[:1])
            del pipe_rx_buffer[:1]
            return res
        
        # Check if buffer starts with a partial leader (e.g. b'0', b'00', b'ii', etc.)
        def is_leader_prefix(buf):
            for leader in KD_LEADERS:
                if leader.startswith(bytes(buf[:min(len(buf), 4)])):
                    return True
            return False

        # If it could be a leader but we don't have 4 bytes yet, wait up to 50ms for more bytes
        if len(pipe_rx_buffer) < 4 and is_leader_prefix(pipe_rx_buffer):
            start_t = time.perf_counter()
            while len(pipe_rx_buffer) < 4 and (time.perf_counter() - start_t) < 0.05:
                if not pull_available(handle):
                    return None
                if len(pipe_rx_buffer) < 4:
                    time.sleep(0.001)

        # Now check full 4-byte leader
        if len(pipe_rx_buffer) >= 4:
            leader = bytes(pipe_rx_buffer[:4])
            start_t = time.perf_counter()

            if leader == b'iiii':
                # Control packet (ACK/NAK/RESEND/RESET): EXACTLY 16 bytes, NO trailing 0xAA!
                while len(pipe_rx_buffer) < 16 and (time.perf_counter() - start_t) < 0.15:
                    if not pull_available(handle):
                        return None
                    if len(pipe_rx_buffer) < 16:
                        time.sleep(0.001)
                
                if len(pipe_rx_buffer) >= 16:
                    res = bytes(pipe_rx_buffer[:16])
                    del pipe_rx_buffer[:16]
                    return res

            elif leader in (b'0000', b'ssss'):
                # Data packet: 16 bytes header + ByteCount payload + 1 byte (0xAA)
                while len(pipe_rx_buffer) < 8 and (time.perf_counter() - start_t) < 0.10:
                    if not pull_available(handle):
                        return None
                    if len(pipe_rx_buffer) < 8:
                        time.sleep(0.001)

                if len(pipe_rx_buffer) >= 8:
                    payload_len = struct.unpack('<H', pipe_rx_buffer[6:8])[0]
                    total_len = 16 + payload_len + 1  # 16-byte header + payload + 0xAA

                    while len(pipe_rx_buffer) < total_len and (time.perf_counter() - start_t) < 0.25:
                        if not pull_available(handle):
                            return None
                        if len(pipe_rx_buffer) < total_len:
                            time.sleep(0.001)

                    if len(pipe_rx_buffer) >= total_len:
                        res = bytes(pipe_rx_buffer[:total_len])
                        del pipe_rx_buffer[:total_len]
                        return res

        # Otherwise, brief coalesce (2ms) so 1-byte writes get batched together
        start_t = time.perf_counter()
        while (time.perf_counter() - start_t) < 0.003:
            if not pull_available(handle):
                return None
            time.sleep(0.0005)
        
        chunk_size = min(len(pipe_rx_buffer), MAX_PAYLOAD)
        res = bytes(pipe_rx_buffer[:chunk_size])
        del pipe_rx_buffer[:chunk_size]
        return res

    def pipe_write(handle, data):
        """Write to named pipe."""
        written = wintypes.DWORD(0)
        ok = kernel32.WriteFile(handle, data, len(data), ctypes.byref(written), None)
        if not ok:
            err = kernel32.GetLastError()
            if err not in (109, 233):
                print(f'[!] pipe WriteFile error: {err}', flush=True)
            return False
        return written.value > 0


pipe_connected = threading.Event()

def udp_to_pipe_thread(udp_sock, pipe_handle):
    """Receive UDP frames from VBox, extract KD payload, write to WinDbg pipe."""
    frame_count = 0
    byte_count = 0
    while True:
        try:
            data, addr = udp_sock.recvfrom(65536)
        except OSError:
            break
        
        payload = parse_kd_frame(data)
        if payload is None:
            print(f'[VBox raw] ({len(data)}B): ethertype={data[12:14].hex() if len(data)>=14 else "?"} src={data[6:12].hex() if len(data)>=12 else "?"}', flush=True)
            continue
        
        frame_count += 1
        byte_count += len(payload)
        
        if frame_count <= 100 or frame_count % 10 == 0 or len(payload) == 1:
            leader = payload[:4]
            extra = ''
            if leader == b'iiii' and len(payload) >= 6:
                ptype = struct.unpack('<H', payload[4:6])[0]
                names = {4: 'ACK', 5: 'RESEND', 6: 'RESET'}
                extra = f' [{names.get(ptype, f"Type {ptype}")}]'
            elif leader in (b'0000', b'ssss') and len(payload) >= 6:
                ptype = struct.unpack('<H', payload[4:6])[0]
                names = {2: 'STATE_CHANGE32', 3: 'STATE_MANIPULATE', 7: 'IO'}
                extra = f' [{names.get(ptype, f"Type {ptype}")}]'
            print(f'[>] Frame #{frame_count} ({len(payload)}B): {payload[:32].hex()}{extra} (total: {byte_count}B)', flush=True)
        
        if sys.platform == 'win32':
            if pipe_connected.is_set():
                if not pipe_write(pipe_handle, payload):
                    # Pipe write failed, likely client disconnected
                    pass


def pipe_to_udp_thread(pipe_handle, udp_sock, vbox_addr):
    """Read from WinDbg pipe, wrap in Ethernet frame, send to VBox via UDP."""
    global pipe_rx_buffer
    frame_count = 0
    byte_count = 0
    while True:
        if sys.platform == 'win32':
            data = pipe_read_kd_message(pipe_handle)
        else:
            data = None
        
        if data is None:
            print('[!] WinDbg disconnected. Waiting for reconnection...', flush=True)
            pipe_connected.clear()
            pipe_rx_buffer = bytearray()
            if sys.platform == 'win32':
                kernel32.DisconnectNamedPipe(pipe_handle)
                ok = kernel32.ConnectNamedPipe(pipe_handle, None)
                if not ok:
                    err = kernel32.GetLastError()
                    if err != 535:  # ERROR_PIPE_CONNECTED
                        print(f'[!] ConnectNamedPipe error: {err}', flush=True)
                        time.sleep(1)
                        continue
                print('[*] WinDbg reconnected!', flush=True)
                pipe_connected.set()
                continue
            else:
                break
        
        if not data:
            continue
        
        frame = build_kd_frame(data)
        if frame is None:
            continue
        
        frame_count += 1
        byte_count += len(data)
        
        if frame_count <= 100 or frame_count % 10 == 0 or len(data) == 1:
            extra = ''
            if data == b'b':
                extra = " [BREAK-IN 'b']"
            elif data[:4] == b'iiii' and len(data) >= 6:
                ptype = struct.unpack('<H', data[4:6])[0]
                names = {4: 'ACK', 5: 'RESEND', 6: 'RESET'}
                extra = f' [{names.get(ptype, f"Type {ptype}")}]'
            elif data[:4] in (b'0000', b'ssss') and len(data) >= 6:
                ptype = struct.unpack('<H', data[4:6])[0]
                names = {2: 'STATE_CHANGE32', 3: 'STATE_MANIPULATE', 7: 'IO'}
                extra = f' [{names.get(ptype, f"Type {ptype}")}]'
            print(f'[<] Frame #{frame_count} ({len(data)}B): {data[:32].hex()}{extra}', flush=True)
        
        udp_sock.sendto(frame, vbox_addr)


def control_thread(udp_sock, vbox_addr):
    """Listen on UDP :40002 for commands like 'break' to inject frames into VBox."""
    cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        cmd_sock.bind(('127.0.0.1', 40002))
    except OSError as e:
        print(f'[!] Control socket bind error: {e}', flush=True)
        return
    
    while True:
        try:
            data, _ = cmd_sock.recvfrom(1024)
            cmd = data.strip().lower()
            if cmd in (b'break', b'b'):
                frame = build_kd_frame(b'b')
                if frame:
                    udp_sock.sendto(frame, vbox_addr)
                    print("[*] [Control] Injected Break-In byte ('b') to VBox!", flush=True)
            elif cmd == b'reset':
                reset_pkt = b'iiii\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                frame = build_kd_frame(reset_pkt)
                if frame:
                    udp_sock.sendto(frame, vbox_addr)
                    print("[*] [Control] Injected KD RESET packet to VBox!", flush=True)
        except Exception:
            time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description='KD Network Bridge for VirtualBox UDP Tunnel')
    parser.add_argument('--sport', type=int, default=40000,
                        help='VBox source port (VBox listens here, we send TO this port). Default: 40000')
    parser.add_argument('--dport', type=int, default=40001,
                        help='VBox dest port (VBox sends TO this port, we listen here). Default: 40001')
    parser.add_argument('--pipe', default=r'\\.\pipe\KdNet',
                        help=r'Named pipe path for WinDbg. Default: \\.\pipe\KdNet')
    parser.add_argument('--host', default='127.0.0.1',
                        help='VBox UDP tunnel destination IP. Default: 127.0.0.1')
    args = parser.parse_args()
    
    print('='*60)
    print('  KD Network Bridge for VirtualBox')
    print('='*60)
    print()
    print('  VBox Setup (run these commands with VM powered off):')
    print(f'    VBoxManage modifyvm "win2000AHCI" --nic1 generic')
    print(f'    VBoxManage modifyvm "win2000AHCI" --nicgenericdrv1 "UDPTunnel"')
    print(f'    VBoxManage modifyvm "win2000AHCI" --nicproperty1 "dest={args.host}"')
    print(f'    VBoxManage modifyvm "win2000AHCI" --nicproperty1 "sport={args.sport}"')
    print(f'    VBoxManage modifyvm "win2000AHCI" --nicproperty1 "dport={args.dport}"')
    print()
    print(f'  Bridge:  listening on UDP :{args.dport}, sending to UDP :{args.sport}')
    print(f'  Control: listening on UDP :40002')
    print(f'  Pipe:    {args.pipe}')
    print()
    
    # Create UDP socket to receive frames from VBox
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(('0.0.0.0', args.dport))
    print(f'[*] UDP socket bound to port {args.dport}')
    
    # VBox address to send frames back to
    vbox_addr = (args.host, args.sport)
    
    # Create named pipe for WinDbg
    if sys.platform == 'win32':
        pipe_handle = create_named_pipe(args.pipe)
        pipe_connected.set()
    else:
        print('[!] Linux/macOS: use socat or a Unix socket (not implemented here)')
        sys.exit(1)
    
    # Start bidirectional threads
    t1 = threading.Thread(target=udp_to_pipe_thread, args=(udp_sock, pipe_handle), daemon=True)
    t2 = threading.Thread(target=pipe_to_udp_thread, args=(pipe_handle, udp_sock, vbox_addr), daemon=True)
    t3 = threading.Thread(target=control_thread, args=(udp_sock, vbox_addr), daemon=True)
    
    t1.start()
    t2.start()
    t3.start()
    
    print('[*] Bridge running. Press Ctrl+C to stop.')
    print()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n[*] Shutting down.')


if __name__ == '__main__':
    main()
