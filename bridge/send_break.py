import socket
import sys

cmd = sys.argv[1].encode() if len(sys.argv) > 1 else b'break'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(cmd, ('127.0.0.1', 40002))
print(f"Sent '{cmd.decode()}' command to kdbridge control port (40002)")
