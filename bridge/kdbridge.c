/*
 * kdbridge.c -- Host-side KD Network Transport Bridge
 *
 * Captures raw Ethernet frames with EtherType 0x88B5 on a local interface
 * (the host-only or LAN interface through which the Windows 2000 target
 * talks), extracts the KD payload bytes, and pipes them to WinDbg via a
 * named pipe so WinDbg sees a byte stream identical to a serial port.
 *
 * Bidirectional: WinDbg's responses are read from the pipe and wrapped
 * back into EtherType 0x88B5 Ethernet frames sent to the target.
 *
 * Build (Windows, Npcap SDK):
 *   cl kdbridge.c /I "%NPCAP_SDK%\Include" /link /LIBPATH:"%NPCAP_SDK%\Lib\x64" wpcap.lib ws2_32.lib
 *
 * Build (Linux, libpcap):
 *   gcc -o kdbridge kdbridge.c -lpcap -lpthread
 *
 * Usage:
 *   kdbridge.exe  <interface>  [\\.\pipe\KdNet]
 *   kdbridge      eth0         [/tmp/kdnet.sock]
 *
 *   Then connect WinDbg:
 *     windbg -k com:pipe,port=\\.\pipe\KdNet,reconnect
 *
 * Wire format (same as kdtransport_net.c target side):
 *   [6 dst mac][6 src mac][2 ethertype=0x88B5 BE][2 payload_len LE][N bytes KD]
 *   EtherType 0x88B5 = "IEEE 802.1 Local Experimental 1"
 */

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <winsock2.h>
  #define PCAP_WINDOWS 1
#else
  #include <pthread.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/socket.h>
  #include <sys/un.h>
  #include <arpa/inet.h>
  #include <errno.h>
#endif

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define KD_ETHERTYPE_BE  0x88B5
#define ETHER_HDR_SIZE   16   /* 6+6+2+2 */
#define MAX_PAYLOAD      1500

/* A broadcast or unicast destination MAC from the target */
static unsigned char g_target_mac[6] = {0};   /* learned from first frame */
static unsigned char g_host_mac[6]   = {0};   /* filled from pcap or config */
static int           g_target_mac_known = 0;

static pcap_t *g_cap = NULL;

#ifdef _WIN32
static HANDLE g_pipe_rd = INVALID_HANDLE_VALUE;   /* WinDbg reads from us */
static HANDLE g_pipe_wr = INVALID_HANDLE_VALUE;   /* WinDbg writes to us  */
static HANDLE g_pipe_srv = INVALID_HANDLE_VALUE;
#else
static int g_sock_fd = -1;
#endif

/* ── Pipe/socket helpers ─────────────────────────────────────────────────── */

static int pipe_read(void *buf, int len)
{
#ifdef _WIN32
    DWORD got = 0;
    if (!ReadFile(g_pipe_srv, buf, (DWORD)len, &got, NULL)) return -1;
    return (int)got;
#else
    return (int)read(g_sock_fd, buf, (size_t)len);
#endif
}

static int pipe_write(const void *buf, int len)
{
#ifdef _WIN32
    DWORD wrote = 0;
    if (!WriteFile(g_pipe_srv, buf, (DWORD)len, &wrote, NULL)) return -1;
    return (int)wrote;
#else
    return (int)write(g_sock_fd, buf, (size_t)len);
#endif
}

/* ── Ethernet helpers ────────────────────────────────────────────────────── */

static void send_kd_frame(const unsigned char *data, int len)
{
    unsigned char frame[ETHER_HDR_SIZE + MAX_PAYLOAD];
    if (len <= 0 || len > MAX_PAYLOAD) return;

    /* dst = target MAC (broadcast if not yet learned) */
    if (g_target_mac_known)
        memcpy(frame, g_target_mac, 6);
    else
        memset(frame, 0xFF, 6);
    /* src = host MAC */
    memcpy(frame + 6, g_host_mac, 6);
    /* EtherType 0x88B5 in big-endian */
    frame[12] = 0x88;
    frame[13] = 0xB5;
    /* Payload length in little-endian (matches target side) */
    frame[14] = (unsigned char)(len & 0xFF);
    frame[15] = (unsigned char)((len >> 8) & 0xFF);
    memcpy(frame + ETHER_HDR_SIZE, data, len);

    int total = ETHER_HDR_SIZE + len;
    if (total < 60) total = 60;   /* Ethernet minimum */

    if (pcap_sendpacket(g_cap, frame, total) != 0)
        fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(g_cap));
}

/* ── pcap callback: frame arrived from target ───────────────────────────── */

static void frame_handler(unsigned char *user,
                           const struct pcap_pkthdr *hdr,
                           const unsigned char *pkt)
{
    (void)user;
    if (hdr->caplen < (unsigned)ETHER_HDR_SIZE) return;

    /* Check EtherType (big-endian on wire) */
    if (pkt[12] != 0x88 || pkt[13] != 0xB5) return;

    /* Learn target MAC from src field */
    if (!g_target_mac_known) {
        memcpy(g_target_mac, pkt + 6, 6);
        g_target_mac_known = 1;
        fprintf(stderr, "Learned target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11]);
    }

    /* Extract payload length (little-endian, as written by target) */
    int payload_len = pkt[14] | (pkt[15] << 8);
    if (payload_len <= 0 || payload_len > MAX_PAYLOAD) return;
    if (hdr->caplen < (unsigned)(ETHER_HDR_SIZE + payload_len)) return;

    /* Forward raw KD bytes to WinDbg pipe */
    const unsigned char *payload = pkt + ETHER_HDR_SIZE;
    int written = pipe_write(payload, payload_len);
    if (written < 0)
        fprintf(stderr, "pipe_write failed\n");
}

/* ── Thread: read from WinDbg pipe, send to target ──────────────────────── */

#ifdef _WIN32
static DWORD WINAPI pipe_to_net_thread(LPVOID arg)
#else
static void *pipe_to_net_thread(void *arg)
#endif
{
    (void)arg;
    unsigned char buf[MAX_PAYLOAD];
    for (;;) {
        int n = pipe_read(buf, sizeof(buf));
        if (n <= 0) break;
        send_kd_frame(buf, n);
    }
    return 0;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: kdbridge <interface-name-or-description> [pipe-name]\n"
            "  Windows example:  kdbridge \"VirtualBox Host-Only\" \\\\.\\pipe\\KdNet\n"
            "  Linux   example:  kdbridge eth0\n");
        return 1;
    }

    const char *iface     = argv[1];
    const char *pipe_name =
#ifdef _WIN32
        argc > 2 ? argv[2] : "\\\\.\\pipe\\KdNet";
#else
        argc > 2 ? argv[2] : "/tmp/kdnet.sock";
#endif

    char errbuf[PCAP_ERRBUF_SIZE];

    /* Open the capture device */
    g_cap = pcap_open_live(iface, 65536, 1, 1, errbuf);
    if (!g_cap) {
        /* Try matching by description (Windows) */
        pcap_if_t *devs, *d;
        if (pcap_findalldevs(&devs, errbuf) == 0) {
            for (d = devs; d; d = d->next) {
                if ((d->description && strstr(d->description, iface)) ||
                    strstr(d->name, iface)) {
                    g_cap = pcap_open_live(d->name, 65536, 1, 1, errbuf);
                    if (g_cap) { fprintf(stderr, "Using: %s (%s)\n",
                                         d->name, d->description ? d->description : ""); break; }
                }
            }
            pcap_freealldevs(devs);
        }
        if (!g_cap) { fprintf(stderr, "Cannot open '%s': %s\n", iface, errbuf); return 1; }
    }

    /* Filter for our EtherType only */
    struct bpf_program bpf;
    if (pcap_compile(g_cap, &bpf, "ether proto 0x88b5", 1, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(g_cap, &bpf);

    printf("Listening on interface for EtherType 0x88B5 ...\n");

    /* Open / create the named pipe for WinDbg */
#ifdef _WIN32
    printf("Creating pipe %s ...\n", pipe_name);
    g_pipe_srv = CreateNamedPipeA(pipe_name,
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1, 65536, 65536, 0, NULL);
    if (g_pipe_srv == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateNamedPipe failed: %lu\n", GetLastError()); return 1; }
    printf("Waiting for WinDbg to connect ...\n");
    ConnectNamedPipe(g_pipe_srv, NULL);
#else
    /* Unix socket */
    unlink(pipe_name);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, pipe_name, sizeof(addr.sun_path)-1);
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 1);
    printf("Waiting for connection on %s ...\n", pipe_name);
    g_sock_fd = accept(srv, NULL, NULL);
#endif

    printf("WinDbg connected. Bridging frames <-> pipe.\n");

    /* Start the pipe->net thread */
#ifdef _WIN32
    HANDLE thr = CreateThread(NULL, 0, pipe_to_net_thread, NULL, 0, NULL);
    if (!thr) { fprintf(stderr, "CreateThread failed\n"); return 1; }
#else
    pthread_t thr;
    pthread_create(&thr, NULL, pipe_to_net_thread, NULL);
#endif

    /* Main loop: capture frames from target, forward to pipe */
    pcap_loop(g_cap, -1, frame_handler, NULL);

    return 0;
}
