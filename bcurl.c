/*
 * bcurl - BHP/1 client (track 2). The protocol is in SPEC.md.
 *
 *   bcurl [-v] [-I] [-o FILE] HOST:PORT/PATH [/PATH ...]
 *
 * Every URL is fetched over the same TCP connection. Requests go out ahead of
 * their responses, each on its own stream, and the bodies are written to
 * stdout in the order the URLs were given, whatever order the server answers
 * in.
 *
 * Exit status: 0 success, 1 network or protocol failure, 2 usage,
 *              4 a response was 4xx, 5 a response was 5xx.
 */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fcntl.h>
#include <io.h>
typedef SOCKET sock_t;
#define BAD_SOCK INVALID_SOCKET
#define close_sock closesocket
#else
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int sock_t;
#define BAD_SOCK (-1)
#define close_sock close
#endif

/* A server that vanishes mid-send should be an error return, not a SIGPIPE. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/*
 * WINDOW is how many requests may be waiting for their response at once. It
 * is bounded so that we always get back to reading: a client that only wrote
 * could fill both socket buffers and deadlock against a server doing the same.
 */
enum { HDR = 8, MAX_PAYLOAD = 65535, WINDOW = 16 };
enum { T_REQUEST = 1, T_RESPONSE = 2, T_DATA = 3 };
enum { F_END = 0x01 };

/* SPEC.md section 4: the static table. Index 0 means the name is spelled out. */
static const char *const NAMES[] = {
    NULL, ":method", ":path", "host", "user-agent", "accept",
    ":status", "content-type", "content-length", "server", "last-modified",
};
enum {
    H_METHOD = 1, H_PATH = 2, H_HOST = 3, H_USER_AGENT = 4, H_ACCEPT = 5,
    H_STATUS = 6, TABLE_SIZE = 10
};

struct field {
    int index;                  /* 0 if the name is not in the table */
    const char *name;           /* NULL for an index this version has no name for */
    size_t nlen;
    const uint8_t *value;
    size_t vlen;
};

struct req {
    const char *path;
    int status;                 /* 0 until the RESPONSE frame arrives */
    int done;                   /* the frame carrying END has arrived */
    uint8_t *held;              /* output waiting for this request's turn */
    size_t len, cap;
};

static int verbose;
static uint8_t frame[HDR + MAX_PAYLOAD];    /* the one frame in hand, either direction */

static void die(int code, const char *fmt, ...)
{
    va_list ap;

    fflush(stdout);
    fputs("bcurl: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(code);
}

static void dump_frame(char dir, const uint8_t *f, size_t n)
{
    static const char *const type[] = { "REQUEST", "RESPONSE", "DATA" };
    unsigned long stream = (unsigned long)f[4] << 24 | f[5] << 16 | f[6] << 8 | f[7];
    size_t off, i;

    fprintf(stderr, "%c %s type=0x%02x flags=0x%02x stream=%lu length=%u\n",
            dir, f[2] >= 1 && f[2] <= 3 ? type[f[2] - 1] : "UNKNOWN",
            f[2], f[3], stream, (unsigned)(n - HDR));
    for (off = 0; off < n; off += 16) {
        char line[128], *p = line;

        p += sprintf(p, "    %04x ", (unsigned)off);
        for (i = 0; i < 16; i++) {
            if (off + i < n)
                p += sprintf(p, " %02x", f[off + i]);
            else
                p += sprintf(p, "   ");
            if (i == 7)
                *p++ = ' ';
        }
        p += sprintf(p, "  |");
        for (i = 0; i < 16 && off + i < n; i++)
            *p++ = isprint(f[off + i]) ? (char)f[off + i] : '.';
        strcpy(p, "|\n");
        fputs(line, stderr);
    }
}

/* ---- socket I/O ------------------------------------------------------- */

/* 1: got all n bytes. 0: the peer closed before the first one. -1: cut short. */
static int read_full(sock_t s, uint8_t *buf, size_t n)
{
    size_t got = 0;

    while (got < n) {
        int r = recv(s, (char *)buf + got, (int)(n - got), 0);

        if (r <= 0)
            return r == 0 && got == 0 ? 0 : -1;
        got += (size_t)r;
    }
    return 1;
}

static int write_all(sock_t s, const uint8_t *buf, size_t n)
{
    while (n > 0) {
        int r = send(s, (const char *)buf, (int)n, MSG_NOSIGNAL);

        if (r <= 0)
            return -1;
        buf += r;
        n -= (size_t)r;
    }
    return 0;
}

/*
 * The only place a socket is created. Walking the address list is not a
 * second connection: an address that refuses us never became one.
 */
static sock_t dial(const char *host, const char *port)
{
    struct addrinfo hints, *res, *ai;
    sock_t s = BAD_SOCK;

    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        die(1, "cannot resolve %s port %s", host, port);
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BAD_SOCK)
            continue;
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0)
            break;
        close_sock(s);
        s = BAD_SOCK;
    }
    freeaddrinfo(res);
    if (s == BAD_SOCK)
        die(1, "cannot connect to %s port %s", host, port);
    return s;
}

/* ---- field blocks (SPEC.md section 4) --------------------------------- */

static size_t put_field(uint8_t *p, size_t at, int index, const char *value)
{
    size_t n = strlen(value);

    p[at] = (uint8_t)index;
    p[at + 1] = (uint8_t)(n >> 8);
    p[at + 2] = (uint8_t)n;
    memcpy(p + at + 3, value, n);
    return at + 3 + n;
}

/* Decode the field at *pos and step past it. -1 if it does not fit the block. */
static int next_field(const uint8_t *p, size_t len, size_t *pos, struct field *f)
{
    size_t i = *pos;
    int k;

    f->index = p[i++];
    f->name = f->index <= TABLE_SIZE ? NAMES[f->index] : NULL;
    f->nlen = f->name ? strlen(f->name) : 0;
    if (f->index == 0) {
        if (i >= len)
            return -1;
        f->nlen = p[i++];
        if (f->nlen == 0 || f->nlen > len - i)
            return -1;
        f->name = (const char *)p + i;
        /* A table name that is spelled out is the same field as its number. */
        for (k = 1; k <= TABLE_SIZE; k++)
            if (strlen(NAMES[k]) == f->nlen && memcmp(NAMES[k], f->name, f->nlen) == 0)
                f->index = k;
        i += f->nlen;
    }
    if (len - i < 2)
        return -1;
    f->vlen = (size_t)p[i] << 8 | p[i + 1];
    i += 2;
    if (f->vlen > len - i)
        return -1;
    f->value = p + i;
    *pos = i + f->vlen;
    return 0;
}

/* The :status of a RESPONSE field block, or 0 if the block is malformed. */
static int parse_status(const uint8_t *p, size_t len)
{
    size_t pos = 0;
    int status = 0;

    while (pos < len) {
        struct field f;

        if (next_field(p, len, &pos, &f) < 0)
            return 0;
        if (f.index != H_STATUS)
            continue;
        if (status || f.vlen != 3 || !isdigit(f.value[0]) || !isdigit(f.value[1])
            || !isdigit(f.value[2]))
            return 0;
        status = (f.value[0] - '0') * 100 + (f.value[1] - '0') * 10 + (f.value[2] - '0');
    }
    return status;
}

static void send_request(sock_t s, uint32_t stream, const char *method, const char *path,
                         const char *authority)
{
    uint8_t *p = frame + HDR;
    size_t n = 0;

    /* 64 covers the three fixed values and five 3-byte field headers. */
    if (strlen(path) + strlen(authority) + 64 > MAX_PAYLOAD)
        die(2, "URL is too long for one frame");
    n = put_field(p, n, H_METHOD, method);
    n = put_field(p, n, H_PATH, path);
    n = put_field(p, n, H_HOST, authority);
    n = put_field(p, n, H_USER_AGENT, "bcurl/1.0");
    n = put_field(p, n, H_ACCEPT, "*/*");
    frame[0] = (uint8_t)(n >> 8);
    frame[1] = (uint8_t)n;
    frame[2] = T_REQUEST;
    frame[3] = 0;
    frame[4] = (uint8_t)(stream >> 24);
    frame[5] = (uint8_t)(stream >> 16);
    frame[6] = (uint8_t)(stream >> 8);
    frame[7] = (uint8_t)stream;
    if (verbose)
        dump_frame('>', frame, HDR + n);
    if (write_all(s, frame, HDR + n) < 0)
        die(1, "connection lost while sending a request");
}

/* ---- output ----------------------------------------------------------- */

static void to_stdout(const void *data, size_t n)
{
    if (n > 0 && fwrite(data, 1, n, stdout) != n)
        die(1, "cannot write the output");
}

/*
 * Output for request r. Only the request at the head of the line with a
 * successful status writes straight through. Everything else is held: later
 * requests until their turn, and error bodies because they go to stderr.
 */
static void emit(struct req *r, int at_head, const void *data, size_t n)
{
    if (n == 0)
        return;
    if (at_head && r->status < 400) {
        to_stdout(data, n);
        return;
    }
    if (r->len + n > r->cap) {
        r->cap = (r->len + n) * 2;
        r->held = realloc(r->held, r->cap);
        if (!r->held)
            die(1, "out of memory");
    }
    memcpy(r->held + r->len, data, n);
    r->len += n;
}

/* -I: the response fields as text, through the same ordering as a body. */
static void emit_fields(struct req *r, int at_head, const uint8_t *p, size_t len)
{
    size_t pos = 0;
    struct field f;

    while (pos < len && next_field(p, len, &pos, &f) == 0) {
        if (!f.name)
            continue;
        emit(r, at_head, f.name, f.nlen);
        emit(r, at_head, ": ", 2);
        emit(r, at_head, f.value, f.vlen);
        emit(r, at_head, "\n", 1);
    }
}

/* ---- command line ----------------------------------------------------- */

static char *copy(const char *s, size_t n)
{
    char *out = malloc(n + 1);

    if (!out)
        die(1, "out of memory");
    memcpy(out, s, n);
    out[n] = 0;
    return out;
}

/*
 * Split "HOST:PORT/PATH". A "scheme://" in front is skipped, an IPv6 literal
 * goes in brackets, and a missing path means "/". The authority is kept as
 * typed for the host field; *host is cut out of a second copy.
 */
static void split_url(const char *url, char **authority, char **host, char **port,
                      const char **path)
{
    const char *slash = strchr(url, '/');
    char *a, *colon;

    if (slash && slash > url && slash[-1] == ':' && slash[1] == '/') {
        url = slash + 2;
        slash = strchr(url, '/');
    }
    *path = slash ? slash : "/";
    *authority = copy(url, slash ? (size_t)(slash - url) : strlen(url));
    a = copy(*authority, strlen(*authority));
    if (a[0] == '[') {
        char *close = strchr(a, ']');

        if (!close || close[1] != ':')
            die(2, "%s: expected HOST:PORT/PATH", url);
        *close = 0;
        *host = a + 1;
        colon = close + 1;
    } else {
        colon = strrchr(a, ':');
        if (!colon)
            die(2, "%s: expected HOST:PORT/PATH", url);
        *host = a;
    }
    *colon = 0;
    *port = colon + 1;
    if (!**host || !**port)
        die(2, "%s: expected HOST:PORT/PATH", url);
}

static void usage(void)
{
    fputs("usage: bcurl [-v] [-I] [-o FILE] HOST:PORT/PATH [/PATH ...]\n"
          "  -v       hexdump every frame to stderr\n"
          "  -I       send HEAD and print the response fields\n"
          "  -o FILE  write the output to FILE instead of stdout\n", stderr);
    exit(2);
}

int main(int argc, char **argv)
{
    const char *method, *outfile = NULL;
    char *authority = NULL, *host = NULL, *port = NULL;
    struct req *reqs;
    size_t n = 0, next = 0, head = 0;
    int i, on = 1, rc = 0, show_fields = 0;
    sock_t s;

    for (i = 1; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
        if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "-I") == 0)
            show_fields = 1;
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
            outfile = argv[++i];
        else
            usage();
    }
    if (i >= argc)
        usage();
    method = show_fields ? "HEAD" : "GET";
    reqs = calloc((size_t)(argc - i), sizeof *reqs);
    if (!reqs)
        die(1, "out of memory");
    for (; i < argc; i++, n++) {
        char *a, *h, *p;

        if (n > 0 && argv[i][0] == '/') {
            reqs[n].path = argv[i];
            continue;
        }
        split_url(argv[i], &a, &h, &p, &reqs[n].path);
        if (n == 0) {
            authority = a;
            host = h;
            port = p;
        } else if (strcmp(a, authority) != 0) {
            /* Checked before connecting: this client has exactly one connection. */
            die(2, "%s is not on %s, and bcurl uses one connection", argv[i], authority);
        }
    }

#ifdef _WIN32
    {
        WSADATA wsa;

        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            die(1, "cannot start Winsock");
        _setmode(_fileno(stdout), _O_BINARY);   /* a body is bytes, not text */
    }
#endif
    if (outfile && !freopen(outfile, "wb", stdout))
        die(1, "cannot write %s", outfile);

    s = dial(host, port);
    /* Several small requests in a row must not wait on Nagle for each other. */
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof on);
    if (verbose)
        fprintf(stderr, "* connected to %s\n", authority);

    while (head < n) {
        struct req *r;
        uint32_t stream;
        size_t len;
        int k;

        for (; next < n && next - head < WINDOW; next++)
            send_request(s, (uint32_t)next + 1, method, reqs[next].path, authority);

        k = read_full(s, frame, HDR);
        len = (size_t)frame[0] << 8 | frame[1];
        if (k == 1 && len > 0)
            k = read_full(s, frame + HDR, len);
        if (k != 1)
            die(1, "connection closed with %u of %u responses unfinished",
                (unsigned)(n - head), (unsigned)n);
        if (verbose)
            dump_frame('<', frame, HDR + len);

        /* A type we do not know, or a REQUEST: already read, so already skipped. */
        if (frame[2] != T_RESPONSE && frame[2] != T_DATA)
            continue;
        /* Stream ids are 1..next, in the order the requests were sent. */
        stream = (uint32_t)frame[4] << 24 | (uint32_t)frame[5] << 16
               | (uint32_t)frame[6] << 8 | frame[7];
        if (stream == 0 || stream > next || reqs[stream - 1].done)
            continue;
        r = &reqs[stream - 1];

        if (frame[2] == T_RESPONSE) {
            if (r->status)
                die(1, "%s: second RESPONSE frame on stream %lu", r->path, (unsigned long)stream);
            r->status = parse_status(frame + HDR, len);
            if (!r->status)
                die(1, "%s: malformed RESPONSE frame", r->path);
            if (r->status >= 500)
                rc = 5;
            else if (r->status >= 400 && rc < 4)
                rc = 4;
            if (show_fields)
                emit_fields(r, r == &reqs[head], frame + HDR, len);
        } else {
            if (!r->status)
                die(1, "%s: DATA before RESPONSE on stream %lu", r->path, (unsigned long)stream);
            emit(r, r == &reqs[head], frame + HDR, len);
        }

        if (!(frame[3] & F_END))
            continue;
        r->done = 1;
        while (head < n && reqs[head].done) {
            r = &reqs[head++];
            if (r->status >= 400) {
                fflush(stdout);
                fprintf(stderr, "bcurl: %s: status %d\n", r->path, r->status);
                if (r->len > 0)
                    fwrite(r->held, 1, r->len, stderr);
            }
            free(r->held);
            /* The next request is now at the head: release what it had to hold. */
            if (head < n && reqs[head].status && reqs[head].status < 400) {
                to_stdout(reqs[head].held, reqs[head].len);
                reqs[head].len = 0;
            }
        }
    }

    close_sock(s);
    if (verbose)
        fprintf(stderr, "* closed after %u request%s on one connection\n", (unsigned)n,
                n == 1 ? "" : "s");
    if (fflush(stdout) != 0)
        die(1, "cannot write the output");
    return rc;
}
