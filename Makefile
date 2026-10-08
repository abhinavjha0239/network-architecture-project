CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra

ifeq ($(OS),Windows_NT)
CC     := gcc
EXE    := .exe
LDLIBS := -lws2_32
PYTHON ?= python
else
EXE    :=
LDLIBS := -pthread
PYTHON ?= python3
endif

all: bserve$(EXE) bcurl$(EXE)

%$(EXE): %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

test: all
	$(PYTHON) tests/interop.py

.PHONY: all test
