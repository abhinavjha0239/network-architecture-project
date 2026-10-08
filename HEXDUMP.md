# One request and one response, byte by byte

This is a real capture of one complete BHP/1 exchange: the client asks for `/index.html`, the server sends the 103-byte file. Three frames cross the wire, 266 bytes in all. Section numbers refer to [SPEC.md](SPEC.md).

```
$ ./bserve ./www 9000
$ ./bcurl -v localhost:9000/index.html
```

## What `bcurl -v` printed

`>` is a frame the client sent, `<` one it received. The offsets on the left count from the start of each frame, so `0000` is always the first byte of a frame header.

```
* connected to localhost:9000
> REQUEST type=0x01 flags=0x00 stream=1 length=55
    0000  00 37 01 00 00 00 00 01  01 00 03 47 45 54 02 00  |.7.........GET..|
    0010  0b 2f 69 6e 64 65 78 2e  68 74 6d 6c 03 00 0e 6c  |./index.html...l|
    0020  6f 63 61 6c 68 6f 73 74  3a 39 30 30 30 04 00 09  |ocalhost:9000...|
    0030  62 63 75 72 6c 2f 31 2e  30 05 00 03 2a 2f 2a     |bcurl/1.0...*/*|
< RESPONSE type=0x02 flags=0x00 stream=1 length=84
    0000  00 54 02 00 00 00 00 01  06 00 03 32 30 30 07 00  |.T.........200..|
    0010  18 74 65 78 74 2f 68 74  6d 6c 3b 20 63 68 61 72  |.text/html; char|
    0020  73 65 74 3d 75 74 66 2d  38 08 00 03 31 30 33 09  |set=utf-8...103.|
    0030  00 0a 62 73 65 72 76 65  2f 31 2e 30 0a 00 1d 54  |..bserve/1.0...T|
    0040  68 75 2c 20 30 38 20 4f  63 74 20 32 30 32 36 20  |hu, 08 Oct 2026 |
    0050  31 30 3a 32 35 3a 30 32  20 47 4d 54              |10:25:02 GMT|
< DATA type=0x03 flags=0x01 stream=1 length=103
    0000  00 67 03 01 00 00 00 01  3c 21 64 6f 63 74 79 70  |.g......<!doctyp|
    0010  65 20 68 74 6d 6c 3e 0a  3c 74 69 74 6c 65 3e 62  |e html>.<title>b|
    0020  73 65 72 76 65 3c 2f 74  69 74 6c 65 3e 0a 3c 68  |serve</title>.<h|
    0030  31 3e 49 74 20 77 6f 72  6b 73 2e 3c 2f 68 31 3e  |1>It works.</h1>|
    0040  0a 3c 70 3e 54 68 69 73  20 70 61 67 65 20 72 65  |.<p>This page re|
    0050  61 63 68 65 64 20 79 6f  75 20 69 6e 20 42 48 50  |ached you in BHP|
    0060  2f 31 20 66 72 61 6d 65  73 2e 3c 2f 70 3e 0a     |/1 frames.</p>.|
* closed after 1 request on one connection
```

## Frame 1: REQUEST, client to server, 63 bytes

The header is the first 8 bytes (§2). Everything after it is the field block (§4).

```
0000  00 37                    Length  55. The payload is the 55 bytes after this
                                       header; the header's own 8 are not counted.
0002  01                       Type    REQUEST
0003  00                       Flags   none. REQUEST defines no flags.
0004  00 00 00 01              Stream  1. The client's first request on this
                                       connection; the server will echo it.

0008  01                       Index   1 = :method. One byte instead of seven.
0009  00 03                    VLen    3
000b  47 45 54                 Value   "GET"

000e  02                       Index   2 = :path
000f  00 0b                    VLen    11
0011  2f 69 6e 64 65 78 2e 68  Value   "/index.h"
0019  74 6d 6c                         "tml"

001c  03                       Index   3 = host
001d  00 0e                    VLen    14
001f  6c 6f 63 61 6c 68 6f 73  Value   "localhos"
0027  74 3a 39 30 30 30                "t:9000"

002d  04                       Index   4 = user-agent
002e  00 09                    VLen    9
0030  62 63 75 72 6c 2f 31 2e  Value   "bcurl/1."
0038  30                               "0"

0039  05                       Index   5 = accept
003a  00 03                    VLen    3
003c  2a 2f 2a                 Value   "*/*"
```

The last value ends at offset `003e`, which is byte 63 of 63: the fields fill the payload exactly, as §4 requires. A server that found a field running past offset `003e` would answer `400` (§5 rule 3).

Every field here has the same three-byte overhead: one byte of Index and two of VLen. None of the names is spelled out, because all five are in the static table.

## Frame 2: RESPONSE, server to client, 92 bytes

```
0000  00 54                    Length  84
0002  02                       Type    RESPONSE
0003  00                       Flags   none. END is clear, so this is not the
                                       last frame of the response: a body follows.
0004  00 00 00 01              Stream  1, copied from the request

0008  06                       Index   6 = :status
0009  00 03                    VLen    3
000b  32 30 30                 Value   "200"

000e  07                       Index   7 = content-type
000f  00 18                    VLen    24
0011  74 65 78 74 2f 68 74 6d  Value   "text/htm"
0019  6c 3b 20 63 68 61 72 73          "l; chars"
0021  65 74 3d 75 74 66 2d 38          "et=utf-8"

0029  08                       Index   8 = content-length
002a  00 03                    VLen    3
002c  31 30 33                 Value   "103". A hint only: the END flag, not
                                       this number, says where the body stops.

002f  09                       Index   9 = server
0030  00 0a                    VLen    10
0032  62 73 65 72 76 65 2f 31  Value   "bserve/1"
003a  2e 30                            ".0"

003c  0a                       Index   10 = last-modified
003d  00 1d                    VLen    29
003f  54 68 75 2c 20 30 38 20  Value   "Thu, 08 "
0047  4f 63 74 20 32 30 32 36          "Oct 2026"
004f  20 31 30 3a 32 35 3a 30          " 10:25:0"
0057  32 20 47 4d 54                   "2 GMT"
```

## Frame 3: DATA, server to client, 111 bytes

```
0000  00 67                    Length  103
0002  03                       Type    DATA
0003  01                       Flags   END (0x01). This frame completes the
                                       response on stream 1.
0004  00 00 00 01              Stream  1

0008  3c 21 64 6f 63 74 79 70  Body    "<!doctyp"
0010  65 20 68 74 6d 6c 3e 0a          "e html>."     0a is the file's newline
0018  3c 74 69 74 6c 65 3e 62          "<title>b"
0020  73 65 72 76 65 3c 2f 74          "serve</t"
0028  69 74 6c 65 3e 0a 3c 68          "itle>.<h"
0030  31 3e 49 74 20 77 6f 72          "1>It wor"
0038  6b 73 2e 3c 2f 68 31 3e          "ks.</h1>"
0040  0a 3c 70 3e 54 68 69 73          ".<p>This"
0048  20 70 61 67 65 20 72 65          " page re"
0050  61 63 68 65 64 20 79 6f          "ached yo"
0058  75 20 69 6e 20 42 48 50          "u in BHP"
0060  2f 31 20 66 72 61 6d 65          "/1 frame"
0068  73 2e 3c 2f 70 3e 0a             "s.</p>."
```

The payload is the file itself, all 103 bytes, with nothing added or escaped. A file larger than 65 535 bytes would arrive as several DATA frames on stream 1, with END set only on the last.

After this frame the client has its answer and closes. The server did not close first: on its side the connection was still open for a stream 2.

## What the numbering bought

The same exchange written as HTTP/1.1 text, with the same header fields, needs 86 bytes for the request and 146 for the response head. Here they are 63 and 92. Most of that saving is the header names: `content-length` is one byte on the wire instead of fourteen.
