/*
 * bserve - BHP/1 file server (track 1). The protocol is in SPEC.md.
 *
 *   bserve [-v] [-b ADDR] ROOT PORT
 *
 * One thread per connection. A thread reads frames until the peer closes: a
 * REQUEST is answered with a RESPONSE frame and the file in DATA frames, and
 * every other frame is read in full and dropped, which is what lets a client
 * from a later version of the protocol talk to this server.
 */
#define _FILE_OFFSET_BITS 64
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
typedef SOCKET sock_t;
#define BAD_SOCK INVALID_SOCKET
#define close_sock closesocket
#define lock_stderr() _lock_file(stderr)
#define unlock_stderr() _unlock_file(stderr)
#else
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int sock_t;
#define BAD_SOCK (-1)
#define close_sock close
#define lock_stderr() flockfile(stderr)
#define unlock_stderr() funlockfile(stderr)
#endif

#define SERVER_NAME "bserve/1.0"

enum { HDR = 8, MAX_PAYLOAD = 65535, CHUNK = 16384 };
enum { T_REQUEST = 1, T_RESPONSE = 2, T_DATA = 3 };
enum { F_END = 0x01 };

/* SPEC.md section 4: the static table. Index 0 means the name is spelled out. */
static const char *const NAMES[] = {
    NULL, ":method", ":path", "host", "user-agent", "accept",
    ":status", "content-type", "content-length", "server", "last-modified",
};
enum {
    H_METHOD = 1, H_PATH = 2, H_STATUS = 6, H_CONTENT_TYPE = 7,
    H_CONTENT_LENGTH = 8, H_SERVER = 9, H_LAST_MODIFIED = 10, TABLE_SIZE = 10
};

struct conn {
    sock_t sock;
    int id;
    uint8_t in[HDR + MAX_PAYLOAD];      /* the frame being read */
    uint8_t out[HDR + MAX_PAYLOAD];     /* the frame being written */
};

struct span {
    const uint8_t *p;
    size_t n;
};

struct field {
    int index;                          /* 0 if the name is not in the table */
    struct span value;
};

static const char *root;
static int verbose;

/* ---- logging ---------------------------------------------------------- */

/* One whole line per call, even with several connections talking at once. */
static void note(const struct conn *c, const char *fmt, ...)
{
    va_list ap;

    lock_stderr();
    fprintf(stderr, "[%d] ", c->id);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    unlock_stderr();
}

/* Bytes from the peer, made safe to log: at most cap-1, unprintables as '?'. */
static const char *printable(char *out, size_t cap, struct span s)
{
    size_t i;

    for (i = 0; i < s.n && i + 1 < cap; i++)
        out[i] = isprint(s.p[i]) ? (char)s.p[i] : '?';
    out[i] = 0;
    return out;
}

static void dump_frame(int id, char dir, const uint8_t *f, size_t n)
{
    static const char *const type[] = { "REQUEST", "RESPONSE", "DATA" };
    unsigned long stream = (unsigned long)f[4] << 24 | f[5] << 16 | f[6] << 8 | f[7];
    size_t off, i;

    lock_stderr();
    fprintf(stderr, "[%d] %c %s type=0x%02x flags=0x%02x stream=%lu length=%u\n",
            id, dir, f[2] >= 1 && f[2] <= 3 ? type[f[2] - 1] : "UNKNOWN",
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
    unlock_stderr();
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
        int r = send(s, (const char *)buf, (int)n, 0);

        if (r <= 0)
            return -1;
        buf += r;
        n -= (size_t)r;
    }
    return 0;
}

/* Send the frame whose payload is already in c->out + HDR. */
static int send_frame(struct conn *c, int type, int flags, uint32_t stream, size_t len)
{
    uint8_t *h = c->out;

    h[0] = (uint8_t)(len >> 8);
    h[1] = (uint8_t)len;
    h[2] = (uint8_t)type;
    h[3] = (uint8_t)flags;
    h[4] = (uint8_t)(stream >> 24);
    h[5] = (uint8_t)(stream >> 16);
    h[6] = (uint8_t)(stream >> 8);
    h[7] = (uint8_t)stream;
    if (verbose)
        dump_frame(c->id, '>', h, HDR + len);
    return write_all(c->sock, h, HDR + len);
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

/*
 * Decode the field at *pos and step past it. Returns NULL, or what is wrong.
 * An index above the table comes back as it is and the caller ignores it:
 * the value length was still there to skip by.
 */
static const char *next_field(const uint8_t *p, size_t len, size_t *pos, struct field *f)
{
    static const char cut[] = "a field runs past the end of the frame";
    size_t i = *pos, nlen;
    int k;

    f->index = p[i++];
    if (f->index == 0) {
        if (i >= len)
            return cut;
        nlen = p[i++];
        if (nlen == 0)
            return "a field has an empty name";
        if (nlen > len - i)
            return cut;
        /* A table name that is spelled out is the same field as its number. */
        for (k = 1; k <= TABLE_SIZE; k++)
            if (strlen(NAMES[k]) == nlen && memcmp(NAMES[k], p + i, nlen) == 0)
                f->index = k;
        i += nlen;
    }
    if (len - i < 2)
        return cut;
    f->value.n = (size_t)p[i] << 8 | p[i + 1];
    i += 2;
    if (f->value.n > len - i)
        return cut;
    f->value.p = p + i;
    *pos = i + f->value.n;
    return NULL;
}

/* SPEC.md section 5 rule 3. Returns NULL, or why the REQUEST is malformed. */
static const char *parse_request(uint32_t stream, const uint8_t *p, size_t len,
                                 struct span *method, struct span *path)
{
    size_t pos = 0;

    method->p = path->p = NULL;
    if (stream == 0)
        return "stream 0 is reserved";
    while (pos < len) {
        struct field f;
        struct span *dst;
        const char *bad = next_field(p, len, &pos, &f);

        if (bad)
            return bad;
        if (f.index != H_METHOD && f.index != H_PATH)
            continue;
        dst = f.index == H_METHOD ? method : path;
        if (dst->p)
            return ":method or :path is repeated";
        *dst = f.value;
    }
    if (!method->p || !path->p)
        return ":method or :path is missing";
    if (path->n == 0 || path->p[0] != '/')
        return ":path does not begin with /";
    return NULL;
}

/* ---- responses -------------------------------------------------------- */

/*
 * A complete error response. Every sender below returns the status it sent,
 * or -1 if the connection is gone.
 */
static int send_error(struct conn *c, uint32_t stream, int status, const char *detail, int head)
{
    const char *reason = status == 400 ? "Bad Request"
                       : status == 404 ? "Not Found" : "Method Not Allowed";
    uint8_t *p = c->out + HDR;
    char text[160], code[8], length[8];
    size_t n = 0;
    int tlen = snprintf(text, sizeof text, "%d %s%s%s\n", status, reason,
                        detail ? ": " : "", detail ? detail : "");

    snprintf(code, sizeof code, "%d", status);
    snprintf(length, sizeof length, "%d", tlen);
    n = put_field(p, n, H_STATUS, code);
    n = put_field(p, n, H_CONTENT_TYPE, "text/plain; charset=utf-8");
    n = put_field(p, n, H_CONTENT_LENGTH, length);
    n = put_field(p, n, H_SERVER, SERVER_NAME);
    if (send_frame(c, T_RESPONSE, head ? F_END : 0, stream, n) < 0)
        return -1;
    if (!head) {
        memcpy(p, text, (size_t)tlen);
        if (send_frame(c, T_DATA, F_END, stream, (size_t)tlen) < 0)
            return -1;
    }
    return status;
}

static int hex_digit(int ch)
{
    return ch >= '0' && ch <= '9' ? ch - '0'
         : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10
         : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
}

/*
 * Turn :path into a file name under the root. Returns 0, or the status to
 * refuse with.
 *
 * The whole path is decoded before it is cut into segments, so an escaped
 * "%2f" cannot hide a segment from the check. No segment may begin with a
 * dot, which rules out ".." (and dotfiles); backslash and colon are refused
 * because on Windows they are a second separator and a drive or stream
 * marker. What is left can only name something below the root.
 *
 * A trailing slash is taken off, because stat() on Windows rejects it, and
 * remembered in *wants_dir so that "/index.html/" does not find the file.
 */
static int map_path(struct span path, char *out, size_t cap, int *wants_dir)
{
    size_t n = strlen(root), i, len = 0;
    char *d = out + n, *seg;

    if (n + path.n + sizeof "/index.html" > cap)
        return 404;
    memcpy(out, root, n);
    for (i = 0; i < path.n && path.p[i] != '?'; i++) {
        int ch = path.p[i];

        if (ch == '%') {
            int hi = i + 2 < path.n ? hex_digit(path.p[i + 1]) : -1;
            int lo = hi < 0 ? -1 : hex_digit(path.p[i + 2]);

            if (lo < 0)
                return 400;
            ch = hi << 4 | lo;
            i += 2;
        }
        if (ch < 0x20 || ch == '\\' || ch == ':')
            return 404;
        d[len++] = (char)ch;
    }
    d[len] = 0;
    for (seg = d; *seg; seg += strcspn(seg, "/"))
        if (*++seg == '.')
            return 404;
    *wants_dir = d[len - 1] == '/';
    while (len > 0 && d[len - 1] == '/')
        d[--len] = 0;
    return 0;
}

static const char *content_type(const char *file)
{
    static const char *const types[][2] = {
        { "html", "text/html; charset=utf-8" }, { "htm", "text/html; charset=utf-8" },
        { "css", "text/css; charset=utf-8" },   { "js", "text/javascript; charset=utf-8" },
        { "txt", "text/plain; charset=utf-8" }, { "json", "application/json" },
        { "svg", "image/svg+xml" },             { "png", "image/png" },
        { "jpg", "image/jpeg" },                { "jpeg", "image/jpeg" },
        { "gif", "image/gif" },                 { "ico", "image/x-icon" },
        { "pdf", "application/pdf" },
    };
    const char *ext = strrchr(file, '.');
    size_t i, k;

    if (ext && !strchr(ext, '/')) {
        ext++;
        for (i = 0; i < sizeof types / sizeof types[0]; i++) {
            for (k = 0; ext[k] && tolower((unsigned char)ext[k]) == types[i][0][k]; k++)
                ;
            if (!ext[k] && !types[i][0][k])
                return types[i][1];
        }
    }
    return "application/octet-stream";
}

static void http_date(time_t t, char *out, size_t cap)
{
    struct tm tm;

    memset(&tm, 0, sizeof tm);
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    strftime(out, cap, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

static int serve_file(struct conn *c, uint32_t stream, struct span path, int head)
{
    uint8_t *p = c->out + HDR;
    char name[4096], length[24], date[40];
    struct stat st;
    size_t n = 0;
    FILE *f;
    int wants_dir, refuse = map_path(path, name, sizeof name, &wants_dir);

    if (refuse)
        return send_error(c, stream, refuse,
                          refuse == 400 ? "bad percent-escape in :path" : NULL, head);
    if (stat(name, &st) == 0 && S_ISDIR(st.st_mode))
        strcat(name, "/index.html");
    else if (wants_dir)
        return send_error(c, stream, 404, NULL, head);
    f = fopen(name, "rb");
    /* Regular files only: on Windows a name like CON or NUL opens a device. */
    if (!f || fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode)) {
        if (f)
            fclose(f);
        return send_error(c, stream, 404, NULL, head);
    }

    snprintf(length, sizeof length, "%llu", (unsigned long long)st.st_size);
    http_date(st.st_mtime, date, sizeof date);
    n = put_field(p, n, H_STATUS, "200");
    n = put_field(p, n, H_CONTENT_TYPE, content_type(name));
    n = put_field(p, n, H_CONTENT_LENGTH, length);
    n = put_field(p, n, H_SERVER, SERVER_NAME);
    n = put_field(p, n, H_LAST_MODIFIED, date);
    if (send_frame(c, T_RESPONSE, head ? F_END : 0, stream, n) < 0)
        goto lost;

    /*
     * A short read is the end of the file, so that frame carries END. It
     * may be empty: a zero-length DATA frame is legal and saves trusting
     * st_size for a file that might be growing.
     */
    while (!head) {
        size_t got = fread(p, 1, CHUNK, f);
        int last = got < CHUNK;

        /* 200 has already gone out; all that is left is to not send END. */
        if (ferror(f))
            goto lost;
        if (send_frame(c, T_DATA, last ? F_END : 0, stream, got) < 0)
            goto lost;
        if (last)
            break;
    }
    fclose(f);
    return 200;

lost:
    fclose(f);
    return -1;
}

static int handle_request(struct conn *c, uint32_t stream, const uint8_t *p, size_t len)
{
    struct span method, path;
    char m[16], u[256];
    int head, status;
    const char *bad = parse_request(stream, p, len, &method, &path);

    if (bad) {
        note(c, "stream %lu: malformed REQUEST (%s) -> 400", (unsigned long)stream, bad);
        return send_error(c, stream, 400, bad, 0);
    }
    head = method.n == 4 && memcmp(method.p, "HEAD", 4) == 0;
    if (head || (method.n == 3 && memcmp(method.p, "GET", 3) == 0))
        status = serve_file(c, stream, path, head);
    else
        status = send_error(c, stream, 405, NULL, 0);
    if (status > 0)
        note(c, "stream %lu: %s %s -> %d", (unsigned long)stream,
             printable(m, sizeof m, method), printable(u, sizeof u, path), status);
    return status;
}

static void serve_connection(struct conn *c)
{
    for (;;) {
        uint8_t *h = c->in;
        uint32_t stream;
        size_t len;
        int r = read_full(c->sock, h, HDR);

        if (r == 0)
            return;                     /* closed between frames: a normal goodbye */
        if (r < 0) {
            send_error(c, 0, 400, "connection ended inside a frame header", 0);
            return;
        }
        len = (size_t)h[0] << 8 | h[1];
        stream = (uint32_t)h[4] << 24 | (uint32_t)h[5] << 16 | (uint32_t)h[6] << 8 | h[7];
        if (len > 0 && read_full(c->sock, h + HDR, len) != 1) {
            send_error(c, stream, 400, "connection ended inside a frame", 0);
            return;
        }
        if (verbose)
            dump_frame(c->id, '<', h, HDR + len);
        /*
         * Only REQUEST means anything to a version 1 server. DATA, RESPONSE
         * and types from later versions have been read in full, so dropping
         * them here leaves us exactly at the next frame header.
         */
        if (h[2] == T_REQUEST && handle_request(c, stream, h + HDR, len) < 0)
            return;
    }
}

/* ---- threads and sockets ---------------------------------------------- */

#ifdef _WIN32
static unsigned __stdcall thread_main(void *arg)
#else
static void *thread_main(void *arg)
#endif
{
    struct conn *c = arg;

    note(c, "connection opened");
    serve_connection(c);
    note(c, "connection closed");
    close_sock(c->sock);
    free(c);
    return 0;
}

static int spawn(struct conn *c)
{
#ifdef _WIN32
    uintptr_t h = _beginthreadex(NULL, 0, thread_main, c, 0, NULL);

    if (h == 0)
        return -1;
    CloseHandle((HANDLE)h);
#else
    pthread_t t;

    if (pthread_create(&t, NULL, thread_main, c) != 0)
        return -1;
    pthread_detach(t);
#endif
    return 0;
}

/*
 * With no address given, listen on one IPv6 socket that also takes IPv4, so
 * "localhost" works whichever way the client resolves it; fall back to plain
 * IPv4 where there is no IPv6.
 */
static sock_t listen_on(const char *addr, const char *port)
{
    static const int families[] = { AF_INET6, AF_INET };
    int i;

    for (i = 0; i < 2; i++) {
        struct addrinfo hints, *res, *ai;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = addr ? AF_UNSPEC : families[i];
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        if (getaddrinfo(addr, port, &hints, &res) != 0)
            res = NULL;
        for (ai = res; ai; ai = ai->ai_next) {
            sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            int off = 0;

            if (s == BAD_SOCK)
                continue;
            if (ai->ai_family == AF_INET6 && !addr)
                setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off, sizeof off);
#ifndef _WIN32
            {
                int on = 1;     /* restart at once; on Windows this would allow port theft */
                setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
            }
#endif
            if (bind(s, ai->ai_addr, (int)ai->ai_addrlen) == 0 && listen(s, 64) == 0) {
                freeaddrinfo(res);
                return s;
            }
            close_sock(s);
        }
        if (res)
            freeaddrinfo(res);
        if (addr)
            break;
    }
    return BAD_SOCK;
}

static int usage(void)
{
    fputs("usage: bserve [-v] [-b ADDR] ROOT PORT\n"
          "  -v       hexdump every frame to stderr\n"
          "  -b ADDR  listen on this address only (default: all)\n", stderr);
    return 2;
}

int main(int argc, char **argv)
{
    const char *addr = NULL, *port;
    struct stat st;
    sock_t ls;
    char *r;
    size_t n;
    int i, id;

    for (i = 1; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
        if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc)
            addr = argv[++i];
        else
            return usage();
    }
    if (argc - i != 2)
        return usage();
    r = argv[i];
    port = argv[i + 1];

    /* "./www/" and "./www" are the same root; stat() on Windows wants the second. */
    for (n = strlen(r); n > 1 && (r[n - 1] == '/' || r[n - 1] == '\\') && r[n - 2] != ':'; )
        r[--n] = 0;
    root = r;
    if (stat(root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "bserve: %s is not a directory\n", root);
        return 1;
    }

#ifdef _WIN32
    {
        WSADATA wsa;

        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fputs("bserve: cannot start Winsock\n", stderr);
            return 1;
        }
    }
#else
    signal(SIGPIPE, SIG_IGN);           /* a vanished client is an error return, not a signal */
#endif

    ls = listen_on(addr, port);
    if (ls == BAD_SOCK) {
        fprintf(stderr, "bserve: cannot listen on %s port %s\n", addr ? addr : "any address", port);
        return 1;
    }
    fprintf(stderr, "bserve: serving %s on port %s\n", root, port);

    for (id = 1;; id++) {
        sock_t s = accept(ls, NULL, NULL);
        struct conn *c;
        int on = 1;

        if (s == BAD_SOCK)
            continue;
        /*
         * A small response is two writes, RESPONSE then DATA. Nagle would
         * hold the second until the first is acknowledged, and the client's
         * delayed ACK turns that into a stall on every request.
         */
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof on);
        c = malloc(sizeof *c);
        if (c) {
            c->sock = s;
            c->id = id;
        }
        if (!c || spawn(c) < 0) {
            free(c);
            close_sock(s);
        }
    }
}
