# Capstone Disassembler Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014

include ../config.mk
include ../functions.mk

# Verbose output?
V ?= 0

INCDIR = ../include
ifndef BUILDDIR
TESTDIR = .
OBJDIR = .
LIBDIR = ..
else
TESTDIR = $(BUILDDIR)/tests
OBJDIR = $(BUILDDIR)/obj/tests
LIBDIR = $(BUILDDIR)
endif

ifeq ($(CROSS),)
CC ?= cc
else
CC = $(CROSS)gcc
endif


CFLAGS += -Wall -I$(INCDIR) -g
LDFLAGS += -L$(LIBDIR)

CFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))
LDFLAGS += $(foreach arch,$(LIBARCHS),-arch $(arch))

CPPFLAGS += -fexceptions -std=c++11 -g

LIBNAME = capstone

BIN_EXT =
AR_EXT = a

# Cygwin?
IS_CYGWIN := $(shell $(CC) -dumpmachine | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
AR_EXT = lib
else
# mingw?
IS_MINGW := $(shell $(CC) --version | grep -i mingw | wc -l)
ifeq ($(IS_MINGW),1)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
AR_EXT = lib
endif
endif

ifeq ($(CAPSTONE_STATIC),yes)
ifeq ($(IS_MINGW),1)
ARCHIVE = $(LIBDIR)/$(LIBNAME).$(AR_EXT)
else ifeq ($(IS_CYGWIN),1)
ARCHIVE = $(LIBDIR)/$(LIBNAME).$(AR_EXT)
else
ARCHIVE = $(LIBDIR)/lib$(LIBNAME).$(AR_EXT)
endif
endif

.PHONY: all clean

OBJS_C = $(addprefix $(OBJDIR)/,$(SOURCES_C:.c=.o))
BINARY_C = $(addprefix $(TESTDIR)/,$(SOURCES_C:.c=$(BIN_EXT)))

#sqlite/sqlite3.c:
#	gcc -g -c -o sqlite/sqlite3.o sqlite/sqlite3.cpp -lpthread -ldl

utils:
	gcc -g -c -o utils.o utils.cpp -std=c++11

SOURCES_CPP = main.cpp parse_mach.cpp jsoncpp.cpp base64.cpp utils.cpp
OBJS_CPP = $(addprefix $(OBJDIR)/,$(SOURCES_CPP:.cpp=.o))
#OBJS_CPP += sqlite/sqlite3.o

main: $(OBJS_CPP)
	g++ $(CPPFLAGS) -o main $(OBJS_CPP) $(LDFLAGS) ../lib$(LIBNAME).a

all: $(BINARY_C) main

clean:
	rm -rf $(OBJS_C) $(BINARY_C) $(OBJS_CPP) main $(TESTDIR)/*.exe $(TESTDIR)/*.static $(OBJDIR)/lib$(LIBNAME).* $(OBJDIR)/$(LIBNAME).*

$(BINARY_C): $(OBJS_C)

$(TESTDIR)/%$(BIN_EXT): $(OBJDIR)/%.o
	@mkdir -p $(@D)
ifeq ($(V),0)
ifeq ($(CAPSTONE_SHARED),yes)
	$(call log,LINK,$(notdir $@))
	@$(link-dynamic)
endif
ifeq ($(CAPSTONE_STATIC),yes)
	$(call log,LINK,$(notdir $(call staticname,$@)))
	@$(link-static)
endif
else
ifeq ($(CAPSTONE_SHARED),yes)
	$(link-dynamic)
endif
ifeq ($(CAPSTONE_STATIC),yes)
	$(link-static)
endif
endif

$(OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,CC,$(@:$(OBJDIR)/%=%))
	@$(compile)
else
	$(compile)
endif


define link-dynamic
	$(CC) $(LDFLAGS) $< -l$(LIBNAME) -o $@
endef


define link-static
	$(CC) $(LDFLAGS) $< $(ARCHIVE) -o $(call staticname,$@)
endef


staticname = $(subst $(BIN_EXT),,$(1)).static$(BIN_EXT)
