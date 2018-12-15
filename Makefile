OBJS_STANDALONE = main.o elf.o emulate.o emulate-instrs.o helper.o channel.o gdb.o mbuf.o hex.o
TARGET_STANDALONE	= anergistic

OBJS_PYTHON = python.o emulate.o emulate-instrs.o helper.o channel.o gdb.o mbuf.o hex.o
TARGET_PYTHON = anergistic.so

UNAME = $(shell uname -s)
WINDOWSID = MINGW32_NT-6.1
MACID = Darwin

ifeq ($(UNAME), $(WINDOWSID))
INCLUDE_PYTHON = C:\Python27\include
EXEC_GENERATE = python instr-generate.py
LIBS = -lws2_32
else ifeq ($(UNAME), $(MACID))
INCLUDE_PYTHON = $(shell brew --prefix python2)/Frameworks/Python.framework/Headers/
EXEC_GENERATE = ./instr-generate.py
LIBS = -lm
PYTHON_LIB = -L $(shell brew --prefix python2)/Frameworks/Python.framework/Versions/Current/lib -lpython2.7
CC = clang
CXX = clang++
else
INCLUDE_PYTHON = /usr/include/python2.7/
EXEC_GENERATE = ./instr-generate.py
LIBS = -lm
PYTHON_LIB = -lpython2.7
CC	 =	gcc
CXX  =  g++
endif


DEPS	 =	Makefile emulate-instrs.h config.h types.h

CFLAGS	 =	-W -Wall -Wextra -O0 -g -I $(INCLUDE_PYTHON)
CXXFLAGS =  -W -Wall -Wextra -O0 -g -std=gnu++17
LDFLAGS	 =	

# CFLAGS += -DDEBUG_INSTR
# CFLAGS += -DDEBUG_DBG
# CFLAGS += -DDEBUG_TRACE
# CFLAGS += -DFAIL_DUMP_REGS
# CFLAGS += -DFAIL_DUMP_LS
# CFLAGS += -DSTOP_DUMP_REGS
# CFLAGS += -DSTOP_DUMP_LS

ifeq ($(UNAME), $(WINDOWSID))
LIBRARY_PATH = C:\Python27\libs\
all: $(TARGET_STANDALONE) $(TARGET_PYTHON)
else
all: $(TARGET_STANDALONE) $(TARGET_PYTHON)
endif

$(TARGET_STANDALONE): $(OBJS_STANDALONE) $(DEPS)
	$(CXX) -o $@ $(OBJS_STANDALONE) $(LIBS)

$(TARGET_PYTHON): $(OBJS_PYTHON) $(DEPS)
	$(CXX) -o $@ $(OBJS_PYTHON) $(LIBS) $(PYTHON_LIB) -shared

%.o: %.c $(DEPS)
	$(CC) -c $(CFLAGS) -o $@ $<

%.o: %.cpp $(DEPS)
	$(CXX) -c $(CXXFLAGS) -o $@ $<

emulate-instrs.h: emulate-instrs.h.in instrs instr-generate.py emulate-instrs.c.in
	$(EXEC_GENERATE) instrs emulate-instrs.h.in emulate-instrs.h emulate-instrs.c.in emulate-instrs.c

emulate-instrs.c: emulate-instrs.h.in instrs instr-generate.py emulate-instrs.c.in
	$(EXEC_GENERATE) instrs emulate-instrs.h.in emulate-instrs.h emulate-instrs.c.in emulate-instrs.c

clean:
	-rm -f $(TARGET_STANDALONE) $(TARGET_PYTHON) $(OBJS_STANDALONE) $(OBJS_PYTHON) emulate-instrs.h emulate-instrs.c
