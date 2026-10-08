#!/usr/bin/env python3
"""Interop tests for BHP/1.

This file is the partner. It speaks the protocol from SPEC.md with its own few
lines of struct.pack and shares nothing with bserve.c or bcurl.c. Part 1 plays
client against the real bserve. Part 2 plays server against the real bcurl and
does what a different implementation is entitled to do: unknown frame types,
interleaved streams, answers out of order. Part 3 runs the two real programs
against each other.

    python tests/interop.py [NAME-FILTER]      (build first; see README.md)
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = ".exe" if os.name == "nt" else ""
BSERVE = os.path.join(TOP, "bserve" + EXE)
BCURL = os.path.join(TOP, "bcurl" + EXE)

# ---- the protocol, from SPEC.md -------------------------------------------

REQUEST, RESPONSE, DATA = 1, 2, 3
END = 0x01
TABLE = [None, ":method", ":path", "host", "user-agent", "accept",
         ":status", "content-type", "content-length", "server", "last-modified"]


def frame(ftype, flags, stream, payload=b""):
    return struct.pack(">HBBI", len(payload), ftype, flags, stream) + payload


def field(name, value, spell=False):
    """One field. `name` is a table index, or a name that is looked up in the
    table unless `spell` asks for it to be written out."""
    if isinstance(value, str):
        value = value.encode()
    if isinstance(name, str) and name in TABLE and not spell:
        name = TABLE.index(name)
    if isinstance(name, int):
        head = bytes([name])
    else:
        head = bytes([0, len(name)]) + name.encode()
    return head + struct.pack(">H", len(value)) + value


def fields(*pairs):
    return b"".join(field(name, value) for name, value in pairs)


def parse_fields(block):
    out, i = [], 0
    while i < len(block):
        index = block[i]
        i += 1
        if index == 0:
            nlen = block[i]
            i += 1
            assert nlen >= 1, "empty field name"
            name = block[i:i + nlen].decode("ascii")
            assert len(name) == nlen, "name runs past the end of the block"
            i += nlen
        else:
            name = TABLE[index] if index < len(TABLE) else None
        (vlen,) = struct.unpack_from(">H", block, i)
        i += 2
        value = block[i:i + vlen]
        assert len(value) == vlen, "value runs past the end of the block"
        i += vlen
        if name is not None:
            out.append((name, value))
    return out


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            if buf:
                raise EOFError("connection ended inside a frame")
            return None
        buf += chunk
    return buf


def read_frame(sock):
    """(type, flags, stream, payload), or None if the peer closed between frames."""
    head = recv_exact(sock, 8)
    if head is None:
        return None
    length, ftype, flags, stream = struct.unpack(">HBBI", head)
    payload = recv_exact(sock, length) if length else b""
    if payload is None:
        raise EOFError("connection ended inside a frame")
    return ftype, flags, stream, payload


TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


# ---- part 1: this file as client, bserve as server ------------------------

PORT = 0        # where bserve is listening
FILES = {}      # name under the root -> contents
SECRET = b"this file is outside the root\n"
GOOD = fields((":method", "GET"), (":path", "/index.html"))


class Client:
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", PORT), timeout=10)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.sock.close()

    def send(self, data):
        self.sock.sendall(data)

    def response(self, stream):
        """Read one whole response and check it is framed as section 3 says.
        Returns (status, fields, body, number of DATA frames)."""
        got = read_frame(self.sock)
        assert got is not None, "server closed instead of answering"
        ftype, flags, sid, payload = got
        assert ftype == RESPONSE, "expected RESPONSE, got type %#x" % ftype
        assert sid == stream, "response on stream %d, request was on %d" % (sid, stream)
        pairs = parse_fields(payload)
        assert [name for name, _ in pairs].count(":status") == 1
        headers = dict(pairs)
        status = headers[":status"]
        assert len(status) == 3 and status.isdigit(), status
        body, ndata = b"", 0
        while not flags & END:
            got = read_frame(self.sock)
            assert got is not None, "server closed before END"
            ftype, flags, sid, payload = got
            assert ftype == DATA and sid == stream
            body += payload
            ndata += 1
        return int(status), headers, body, ndata

    def get(self, stream, path, method="GET"):
        self.send(frame(REQUEST, 0, stream, fields((":method", method), (":path", path))))
        return self.response(stream)

    def quiet(self, seconds=0.3):
        """True if the server neither sends anything nor closes for a while."""
        self.sock.settimeout(seconds)
        try:
            self.sock.recv(1)
        except socket.timeout:
            return True
        finally:
            self.sock.settimeout(10)
        return False


@test
def server_get():
    with Client() as c:
        status, h, body, _ = c.get(1, "/index.html")
        assert status == 200
        assert body == FILES["index.html"]
        assert h["content-length"] == str(len(body)).encode()
        assert h["content-type"].startswith(b"text/html")
        assert h["last-modified"].endswith(b" GMT")
        assert h["server"]


@test
def server_keeps_the_connection_open():
    with Client() as c:
        for stream in (1, 2, 3, 70000, 0xFFFFFFFF):
            status, _, body, _ = c.get(stream, "/index.html")
            assert status == 200 and body == FILES["index.html"]
        assert c.quiet(), "server closed, or spoke without being asked"


@test
def server_head():
    with Client() as c:
        status, h, body, ndata = c.get(1, "/big.bin", "HEAD")
        assert status == 200 and ndata == 0 and body == b""
        assert h["content-length"] == str(len(FILES["big.bin"])).encode()
        assert c.get(2, "/nope", "HEAD")[0] == 404


@test
def server_404():
    with Client() as c:
        status, h, body, _ = c.get(1, "/nope.html")
        assert status == 404 and body
        assert c.get(2, "/index.html")[0] == 200


@test
def server_405():
    with Client() as c:
        assert c.get(1, "/index.html", "POST")[0] == 405
        # A request body is DATA from a client: rule 2, dropped without comment.
        c.send(frame(DATA, END, 1, b"a body version 1 has no use for"))
        assert c.quiet()
        assert c.get(2, "/index.html")[0] == 200


@test
def server_splits_a_big_file():
    with Client() as c:
        status, h, body, ndata = c.get(1, "/big.bin")
        assert status == 200 and body == FILES["big.bin"]
        assert ndata >= 4, "200 kB cannot fit in %d frames" % ndata
        status, _, body, _ = c.get(2, "/empty.txt")
        assert status == 200 and body == b""


@test
def server_skips_unknown_frame_types():
    with Client() as c:
        c.send(frame(0x7F, 0xFF, 0, b"\xAA" * 1000))
        c.send(frame(0x00, 0x00, 9))
        c.send(frame(0xFF, 0x01, 0xFFFFFFFF, os.urandom(65535)))
        assert c.quiet(), "server replied to, or closed on, an unknown frame type"
        status, _, body, _ = c.get(1, "/index.html")
        assert status == 200 and body == FILES["index.html"]
        c.send(frame(0x04, 0, 1, GOOD))
        assert c.quiet()


@test
def server_drops_known_frames_in_the_wrong_place():
    with Client() as c:
        c.send(frame(DATA, END, 1, b"stray"))
        c.send(frame(RESPONSE, END, 1, fields((":status", "200"))))
        assert c.quiet()
        assert c.get(1, "/index.html")[0] == 200


@test
def server_400_on_a_malformed_request():
    cases = {
        "value runs past the frame": field(":method", "GET") + b"\x02\x00\x40/short",
        "cut inside VLen": GOOD + b"\x03\x00",
        "cut after Index": GOOD + b"\x03",
        "cut after the 0x00": GOOD + b"\x00",
        "empty spelled name": GOOD + b"\x00\x00\x00\x01x",
        "spelled name runs past the frame": GOOD + b"\x00\x09abc",
        "empty payload": b"",
        "no :path": fields((":method", "GET")),
        "no :method": fields((":path", "/index.html")),
        ":path twice": GOOD + field(":path", "/index.html"),
        ":method twice, once spelled": GOOD + field(":method", "GET", spell=True),
        ":path without the leading slash": fields((":method", "GET"), (":path", "index.html")),
        "empty :path": fields((":method", "GET"), (":path", "")),
    }
    with Client() as c:
        stream = 0
        for name, payload in cases.items():
            stream += 1
            c.send(frame(REQUEST, 0, stream, payload))
            status, _, body, _ = c.response(stream)
            assert status == 400, "%s: got %d" % (name, status)
            # Length was honoured, so the very next frame must still parse.
            stream += 1
            assert c.get(stream, "/index.html")[0] == 200, "connection unusable after: " + name
        c.send(frame(REQUEST, 0, 0, GOOD))
        assert c.response(0)[0] == 400, "stream 0"


@test
def server_400_when_the_connection_ends_inside_a_frame():
    with Client() as c:
        c.send(struct.pack(">HBBI", 100, REQUEST, 0, 5) + GOOD)
        c.sock.shutdown(socket.SHUT_WR)
        assert c.response(5)[0] == 400
        assert read_frame(c.sock) is None, "server did not close"
    with Client() as c:
        c.send(b"\x00\x10\x01")
        c.sock.shutdown(socket.SHUT_WR)
        assert c.response(0)[0] == 400
        assert read_frame(c.sock) is None


@test
def server_ignores_fields_it_does_not_know():
    payload = (field(200, "an index from the future") + field("x-future", "1") + GOOD
               + field(11, b"") + field(255, os.urandom(300)))
    with Client() as c:
        c.send(frame(REQUEST, 0, 1, payload))
        assert c.response(1)[0] == 200


@test
def server_accepts_table_names_spelled_out():
    payload = field(":path", "/index.html", spell=True) + field(":method", "GET", spell=True)
    with Client() as c:
        c.send(frame(REQUEST, 0, 1, payload))
        status, _, body, _ = c.response(1)
        assert status == 200 and body == FILES["index.html"]


@test
def server_ignores_undefined_flags():
    with Client() as c:
        c.send(frame(REQUEST, 0xFF, 1, GOOD))
        status, _, body, _ = c.response(1)
        assert status == 200 and body == FILES["index.html"]


@test
def server_maps_paths():
    with Client() as c:
        same = {"/": "index.html", "/index.html?x=1&y=/../": "index.html", "/?q": "index.html",
                "/%69ndex.html": "index.html", "//index.html": "index.html",
                "/hello%20world.txt": "hello world.txt", "/sub": "sub/index.html",
                "/sub/": "sub/index.html", "/sub/page.html": "sub/page.html"}
        for stream, (path, name) in enumerate(same.items(), 1):
            status, _, body, _ = c.get(stream, path)
            assert status == 200 and body == FILES[name], path
        assert c.get(50, "/bad%zz")[0] == 400
        assert c.get(51, "/cut%4")[0] == 400
        assert c.get(52, "/index.html/")[0] == 404, "a file is not a directory"
        assert c.get(53, "/sub/nope")[0] == 404
        assert c.get(54, "/" + "a" * 60000)[0] == 404


@test
def server_never_leaves_its_root():
    outside = os.path.join(os.path.dirname(ROOT), "secret.txt").replace("\\", "/")
    attempts = [
        "/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt", "/%2e%2e%2fsecret.txt",
        "/sub/../../secret.txt", "/sub%2f..%2f..%2fsecret.txt", "/sub/%2e%2e/%2e%2e/secret.txt",
        "//../secret.txt", "/./../secret.txt", "/.../secret.txt", "/..;/secret.txt",
        "/..\\secret.txt", "/%5c..%5csecret.txt", "/..%5csecret.txt", "/sub/..%5c..%5csecret.txt",
        "/sub\\..\\..\\secret.txt", "/..%00/secret.txt", "/index.html%00/../../secret.txt",
        "/" + outside, "//" + outside, "/%2f" + outside.lstrip("/"),
        "/.hidden", "/sub/.hidden",
    ]
    with Client() as c:
        for stream, path in enumerate(attempts, 1):
            status, _, body, _ = c.get(stream, path)
            assert status != 200 and SECRET not in body and b"dotfile" not in body, path
        assert c.get(999, "/index.html")[0] == 200


@test
def server_reads_a_frame_that_arrives_a_byte_at_a_time():
    with Client() as c:
        c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for byte in frame(0x55, 0, 0, b"skip me") + frame(REQUEST, 0, 7, GOOD):
            c.send(bytes([byte]))
            time.sleep(0.002)
        status, _, body, _ = c.response(7)
        assert status == 200 and body == FILES["index.html"]


@test
def server_answers_requests_sent_ahead():
    def req(stream, path):
        return frame(REQUEST, 0, stream, fields((":method", "GET"), (":path", path)))

    with Client() as c:
        c.send(req(11, "/index.html") + req(12, "/big.bin") + req(13, "/nope") + req(14, "/sub/"))
        # bserve answers in order; the spec would also allow any other order.
        assert c.response(11)[2] == FILES["index.html"]
        assert c.response(12)[2] == FILES["big.bin"]
        assert c.response(13)[0] == 404
        assert c.response(14)[2] == FILES["sub/index.html"]


@test
def server_serves_two_connections_at_once():
    request = frame(REQUEST, 0, 2, GOOD)
    with Client() as idle, Client() as busy:
        idle.send(request[:3])          # part of a frame header, then silence
        assert busy.get(1, "/index.html")[0] == 200
        idle.send(request[3:])
        assert idle.response(2)[0] == 200


# ---- part 2: this file as server, bcurl as client -------------------------

def run_bcurl(args, script=None):
    """Run bcurl against a server played by `script(conn)`. "{port}" in an
    argument is replaced by the port. Returns (exit status, stdout, stderr,
    number of connections bcurl opened)."""
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(8)
    ls.settimeout(0.1)
    port = ls.getsockname()[1]
    accepted, failures, stop = [], [], threading.Event()

    def acceptor():
        while not stop.is_set():
            try:
                conn, _ = ls.accept()
            except socket.timeout:
                continue
            accepted.append(conn)
            try:
                if len(accepted) == 1 and script:
                    conn.settimeout(10)
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    script(conn)
            except Exception as exc:    # report it from the main thread
                failures.append(exc)
            finally:
                conn.close()

    thread = threading.Thread(target=acceptor, daemon=True)
    thread.start()
    try:
        done = subprocess.run([BCURL] + [a.replace("{port}", str(port)) for a in args],
                              capture_output=True, timeout=30)
        time.sleep(0.2)                 # room for a second connection to show itself
    finally:
        stop.set()
        thread.join(15)
        ls.close()
    if failures:
        raise failures[0]
    return done.returncode, done.stdout, done.stderr, len(accepted)


def read_requests(conn, n):
    """Read n REQUEST frames and check each one. Returns [(stream, fields)]."""
    out = []
    while len(out) < n:
        got = read_frame(conn)
        assert got is not None, "client closed before sending its requests"
        ftype, flags, stream, payload = got
        assert ftype == REQUEST, "client sent frame type %#x" % ftype
        assert flags == 0, "client set undefined flags"
        assert stream != 0, "client used stream 0"
        pairs = parse_fields(payload)
        names = [name for name, _ in pairs]
        assert names.count(":method") == 1 and names.count(":path") == 1
        assert all(name == name.lower() for name in names)
        out.append((stream, dict(pairs)))
    assert len({stream for stream, _ in out}) == n, "client reused a stream id"
    return out


def response(stream, status, body=b"", pieces=1):
    """The frames of one response, as a list, so that a test can shuffle them
    in with another stream's."""
    out = [frame(RESPONSE, 0 if body else END, stream,
                 fields((":status", str(status)), ("content-length", str(len(body)))))]
    step = max(1, -(-len(body) // pieces))
    chunks = [body[i:i + step] for i in range(0, len(body), step)]
    for i, chunk in enumerate(chunks):
        out.append(frame(DATA, END if i == len(chunks) - 1 else 0, stream, chunk))
    return out


def expect_close(conn):
    """The client has its answers and should now close, sending nothing more.
    A reset counts: it means the client closed with frames of ours unread,
    which it may do once every response it asked for is complete."""
    try:
        got = read_frame(conn)
    except ConnectionError:
        return
    assert got is None, "client sent something after its last response"


A, B, C = b"alpha " * 500 + b"\n", b"bravo " * 300 + b"\n", b"charlie\n"


@test
def client_one_request():
    seen = []

    def script(conn):
        (stream, h), = read_requests(conn, 1)
        seen.append(h)
        conn.sendall(b"".join(response(stream, 200, A, pieces=3)))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a/b.txt?q=1"], script)
    assert (code, out, conns) == (0, A, 1), (code, err)
    assert seen[0][":method"] == b"GET" and seen[0][":path"] == b"/a/b.txt?q=1"
    assert seen[0]["host"].startswith(b"127.0.0.1:")


@test
def client_uses_one_connection_for_every_url():
    bodies = {b"/a": A, b"/b": B, b"/c": C}

    def script(conn):
        for _ in range(3):
            (stream, h), = read_requests(conn, 1)
            conn.sendall(b"".join(response(stream, 200, bodies[h[":path"]])))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a", "/b", "bhp://127.0.0.1:{port}/c"],
                                      script)
    assert (code, out, conns) == (0, A + B + C, 1), (code, conns, err)


@test
def client_uses_one_connection_for_forty_urls():
    def script(conn):
        for _ in range(40):
            (stream, h), = read_requests(conn, 1)
            conn.sendall(b"".join(response(stream, 200, h[":path"] + b"\n")))
        expect_close(conn)

    paths = ["/%d" % i for i in range(40)]
    code, out, err, conns = run_bcurl(["127.0.0.1:{port}" + paths[0]] + paths[1:], script)
    assert (code, conns) == (0, 1), (code, conns, err)
    assert out == "".join(p + "\n" for p in paths).encode()


@test
def client_sorts_interleaved_responses_that_finish_out_of_order():
    def script(conn):
        stream = {h[":path"]: s for s, h in read_requests(conn, 3)}
        a = response(stream[b"/a"], 200, A, pieces=3)
        b = response(stream[b"/b"], 200, B, pieces=3)
        c = response(stream[b"/c"], 200, C)
        # c arrives whole and first; b and a are shuffled, and b finishes before a.
        order = c + [b[0], a[0], b[1], a[1], b[2], b[3], a[2], a[3]]
        conn.sendall(b"".join(order))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a", "/b", "/c"], script)
    assert (code, out, conns) == (0, A + B + C, 1), (code, err)


@test
def client_skips_unknown_frame_types():
    def script(conn):
        (stream, _), = read_requests(conn, 1)
        r = response(stream, 200, A, pieces=2)
        conn.sendall(frame(0x7F, 0xFF, 0, b"settings from version 2") + r[0]
                     + frame(0x00, 0, stream)
                     + frame(0xFF, END, stream, os.urandom(65535))     # END on a type it cannot know
                     + r[1] + frame(0x04, END, stream, b"x") + r[2] + frame(0x09, 0, 0, b"bye"))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a"], script)
    assert (code, out, conns) == (0, A, 1), (code, err)


@test
def client_drops_frames_that_are_not_for_it():
    def script(conn):
        (stream, _), = read_requests(conn, 1)
        strays = (response(stream + 1000, 200, b"someone else's body\n")
                  + [frame(REQUEST, 0, stream, GOOD)] + response(0, 400, b"stream zero\n"))
        r = response(stream, 200, C)
        conn.sendall(b"".join(strays[:2]) + r[0] + b"".join(strays[2:]) + r[1])
        # and after the stream is finished, more frames on it
        conn.sendall(frame(DATA, END, stream, b"late\n"))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/c"], script)
    assert (code, out, conns) == (0, C, 1), (code, err)


@test
def client_ignores_fields_it_does_not_know():
    def script(conn):
        (stream, _), = read_requests(conn, 1)
        block = (field(77, "an index from the future") + field("x-new", "1")
                 + field(":status", "200", spell=True) + field(255, os.urandom(500)))
        conn.sendall(frame(RESPONSE, 0xFE, stream, block) + frame(DATA, 0xFF, stream, C))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/c"], script)
    assert (code, out) == (0, C), (code, err)


@test
def client_exit_status_follows_the_response():
    for status, ok in ((200, True), (204, True), (400, False), (404, False), (500, False),
                       (503, False)):
        def script(conn):
            (stream, _), = read_requests(conn, 1)
            conn.sendall(b"".join(response(stream, status, b"the body for %d\n" % status)))
            expect_close(conn)

        code, out, err, conns = run_bcurl(["127.0.0.1:{port}/x"], script)
        assert (code == 0) == ok, "status %d gave exit %d" % (status, code)
        if not ok:
            assert out == b"", "an error body reached stdout"
            assert str(status).encode() in err


@test
def client_fetches_the_rest_when_one_url_fails():
    def script(conn):
        for status, body in ((200, A), (404, b"no such thing\n"), (200, C)):
            (stream, _), = read_requests(conn, 1)
            conn.sendall(b"".join(response(stream, status, body)))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a", "/b", "/c"], script)
    assert code != 0 and out == A + C and conns == 1, (code, err)


@test
def client_fails_when_the_server_goes_away():
    def cut_mid_body(conn):
        (stream, _), = read_requests(conn, 1)
        conn.sendall(b"".join(response(stream, 200, A, pieces=3)[:2]))

    def cut_mid_frame(conn):
        (stream, _), = read_requests(conn, 1)
        conn.sendall(b"".join(response(stream, 200, A))[:-10])

    def never_answers(conn):
        read_requests(conn, 1)

    for script in (cut_mid_body, cut_mid_frame, never_answers):
        code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a"], script)
        assert code != 0 and conns == 1, script.__name__


@test
def client_fails_on_a_malformed_response():
    blocks = {
        "no :status": fields(("content-length", "0")),
        ":status twice": fields((":status", "200"), (":status", "200")),
        ":status not three digits": fields((":status", "OK")),
        "field runs past the frame": b"\x06\x00\x09200",
    }
    for name, block in blocks.items():
        def script(conn):
            (stream, _), = read_requests(conn, 1)
            conn.sendall(frame(RESPONSE, END, stream, block))
            expect_close(conn)

        code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a"], script)
        assert code != 0 and out == b"", name

    def data_first(conn):
        (stream, _), = read_requests(conn, 1)
        conn.sendall(frame(DATA, END, stream, b"body with no RESPONSE"))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a"], data_first)
    assert code != 0 and out == b""


@test
def client_accepts_a_response_with_no_body():
    def script(conn):
        (s1, _), (s2, _) = read_requests(conn, 2)
        conn.sendall(frame(RESPONSE, END, s1, fields((":status", "200")))
                     + frame(RESPONSE, 0, s2, fields((":status", "200")))
                     + frame(DATA, 0, s2) + frame(DATA, END, s2))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a", "/b"], script)
    assert (code, out, conns) == (0, b"", 1), (code, err)


@test
def client_passes_a_binary_body_through_untouched():
    body = bytes(range(256)) * 300 + b"\r\n\x1a\n\x00"

    def script(conn):
        (stream, _), = read_requests(conn, 1)
        conn.sendall(b"".join(response(stream, 200, body, pieces=5)))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/blob"], script)
    assert code == 0 and out == body, (code, len(out), len(body))

    target = os.path.join(os.path.dirname(ROOT), "saved.bin")
    code, out, err, conns = run_bcurl(["-o", target, "127.0.0.1:{port}/blob"], script)
    with open(target, "rb") as f:
        assert code == 0 and out == b"" and f.read() == body


@test
def client_reads_frames_that_arrive_a_byte_at_a_time():
    def script(conn):
        (stream, _), = read_requests(conn, 1)
        for byte in frame(0x33, 0, 0, b"skip") + b"".join(response(stream, 200, C, pieces=2)):
            conn.sendall(bytes([byte]))
            time.sleep(0.002)
        expect_close(conn)

    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/c"], script)
    assert (code, out) == (0, C), (code, err)


@test
def client_verbose_hexdumps_every_frame():
    wire = []

    def script(conn):
        ftype, flags, stream, payload = read_frame(conn)
        wire.append(frame(ftype, flags, stream, payload))
        wire.append(frame(0x7F, 0, 0, b"a type bcurl does not know"))
        wire.extend(response(stream, 200, C))
        conn.sendall(b"".join(wire[1:]))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["-v", "127.0.0.1:{port}/c"], script)
    assert (code, out) == (0, C), "the dump must not leak into stdout"
    assert len(wire) == 4
    text = " ".join(err.decode().split())
    for raw in wire:
        for off in range(0, len(raw), 8):       # the dump has a gap every 8 bytes
            row = " ".join("%02x" % byte for byte in raw[off:off + 8])
            assert row in text, "frame missing from -v output: " + row


@test
def client_head():
    seen = []

    def script(conn):
        (stream, h), = read_requests(conn, 1)
        seen.append(h[":method"])
        conn.sendall(frame(RESPONSE, END, stream,
                           fields((":status", "200"), ("content-length", "1234"))
                           + field(99, "x") + field("x-extra", "yes")))
        expect_close(conn)

    code, out, err, conns = run_bcurl(["-I", "127.0.0.1:{port}/a"], script)
    assert code == 0 and seen == [b"HEAD"], (code, err)
    assert out.split(b"\n") == [b":status: 200", b"content-length: 1234", b"x-extra: yes", b""]


@test
def client_refuses_a_url_that_would_need_a_second_connection():
    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a", "127.0.0.2:{port}/b"])
    assert code == 2 and conns == 0, (code, conns)
    code, out, err, conns = run_bcurl(["127.0.0.1:{port}/a", "127.0.0.1:1/b"])
    assert code == 2 and conns == 0, (code, conns)
    assert run_bcurl(["no-port-here/a"])[0] == 2
    assert run_bcurl([])[0] == 2


# ---- part 3: the real bcurl against the real bserve -----------------------

def bcurl(*args):
    done = subprocess.run([BCURL] + list(args), capture_output=True, timeout=30)
    return done.returncode, done.stdout, done.stderr


@test
def together_get():
    base = "127.0.0.1:%d" % PORT
    code, out, err = bcurl(base + "/index.html", "/big.bin", "/hello%20world.txt", "/sub/")
    assert code == 0, err
    assert out == (FILES["index.html"] + FILES["big.bin"] + FILES["hello world.txt"]
                   + FILES["sub/index.html"])


@test
def together_errors():
    base = "127.0.0.1:%d" % PORT
    code, out, err = bcurl(base + "/nope")
    assert code == 4 and out == b"" and b"404" in err
    code, out, err = bcurl(base + "/index.html", "/nope", "/empty.txt", "/sub/page.html")
    assert code == 4 and out == FILES["index.html"] + FILES["sub/page.html"]
    code, out, err = bcurl("-I", base + "/big.bin")
    assert code == 0 and b"content-length: %d\n" % len(FILES["big.bin"]) in out
    assert bcurl("127.0.0.1:1/")[0] == 1         # nothing listening there


# ---- runner ---------------------------------------------------------------

ROOT = ""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    global PORT, ROOT
    for exe in (BSERVE, BCURL):
        if not os.path.exists(exe):
            sys.exit("%s is missing: build first (see README.md)" % exe)
    wanted = sys.argv[1] if len(sys.argv) > 1 else ""

    with tempfile.TemporaryDirectory() as tmp:
        ROOT = os.path.join(tmp, "www")
        FILES.update({
            "index.html": b"<!doctype html>\n<title>t</title>\n<p>hello</p>\n",
            "hello world.txt": b"a file with a space in its name\r\n",
            "big.bin": os.urandom(200000),
            "empty.txt": b"",
            "sub/index.html": b"<p>the index of sub</p>\n",
            "sub/page.html": b"<p>a page in sub</p>\n",
            ".hidden": b"a dotfile\n",
            "sub/.hidden": b"a dotfile\n",
        })
        for name, data in FILES.items():
            path = os.path.join(ROOT, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
        with open(os.path.join(tmp, "secret.txt"), "wb") as f:
            f.write(SECRET)

        PORT = free_port()
        log = open(os.path.join(tmp, "bserve.log"), "wb")
        # A trailing slash on the root, as a user might type it.
        server = subprocess.Popen([BSERVE, "-b", "127.0.0.1", ROOT + "/", str(PORT)], stderr=log)
        failed = 0
        try:
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                sys.exit("bserve did not start listening")

            for fn in TESTS:
                if wanted not in fn.__name__:
                    continue
                try:
                    fn()
                    print("ok    " + fn.__name__)
                except Exception as exc:
                    failed += 1
                    print("FAIL  %s: %s: %s" % (fn.__name__, type(exc).__name__, exc))
            assert server.poll() is None, "bserve died during the tests"
        finally:
            server.kill()
            server.wait()
            log.close()
            if failed:
                with open(log.name, "rb") as f:
                    print("--- last lines of the bserve log ---")
                    print(b"".join(f.readlines()[-15:]).decode(errors="replace"))

    print("%d failed" % failed if failed else "all passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
