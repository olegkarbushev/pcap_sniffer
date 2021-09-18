include common.mk

MAIN_TARGET = pcap_sniffer
LIB_TARGET = #<lib_name>.$(LIB_EXT)

SRC_DIR = src

CXX_COMMON_SRC =

CXX_SRC = $(SRC_DIR)/main.c
CXX_SRC += $(SRC_DIR)/packet_handler.c
CXX_SRC += $(SRC_DIR)/socket_registry.c
CXX_SRC += $(CXX_COMMON_SRC)

CXX_LIB_SRC =
CXX_LIB_SRC += $(CXX_COMMON_SRC)

INCLUDES = -I$(SRC_DIR)/
INCLUDES += -I$(SRC_DIR)/include/
INCLUDES += -I$(SRC_DIR)/libpcap/
# this command will obtain required include folders for Glib
INCLUDES += $(shell pkg-config --cflags glib-2.0)

VPATH = $(dir $(CXX_SRC))

OBJ_DIR := obj
BIN_DIR := bin

# collecting obj files for binary target and place to OBJ_DIR
CXX_OBJS_STRIPPED += $(patsubst %.c, %.o, $(notdir $(filter %.c, $(CXX_SRC))))
CXX_OBJS := $(addprefix $(OBJ_DIR)/, $(CXX_OBJS_STRIPPED))

# collecting obj files for library target and place to OBJ_DIR
CXX_LIB_OBJS_STRIPPED += $(patsubst %.c, %.o, $(notdir $(filter %.c, $(CXX_LIB_SRC))))
CXX_LIB_OBJS := $(addprefix $(OBJ_DIR)/, $(CXX_LIB_OBJS_STRIPPED))

LIBS = -lpcap
LIBS += -lpthread
# required by libpcap, to avoid errors: reference to "dbus_* is undefined"
LIBS += -ldbus-1
# this command will obtain the specific Glib version
LIBS += $(shell pkg-config --libs glib-2.0)

LIBS_DIR = -L$(SRC_DIR)/libpcap/


CXX = gcc

CXXFLAGS = -Wall -g $(OS_FLAGS)
CXXFLAGS += $(INCLUDES)

LDFLAGS = $(LIBS_DIR) $(LIBS) $(OS_FLAGS)

.PHONY: all clean lib

# all target
all: $(OBJ_DIR) $(BIN_DIR) $(MAIN_TARGET)

lib: $(OBJ_DIR) $(BIN_DIR) $(LIB_TARGET)

# create './obj/' directory
$(OBJ_DIR):
	@echo "\n\r*** creating '$(OBJ_DIR)' folder"
	mkdir $(OBJ_DIR)

# create './bin/' directory
$(BIN_DIR):
	@echo "\n\r*** creating '$(BIN_DIR)' folder"
	mkdir $(BIN_DIR)

# link bin file
$(LIB_TARGET): $(CXX_LIB_OBJS)
	@echo "\n\r*** linking '$(LIB_TARGET)' @='$@' "
	$(CXX) $(CXX_LIB_OBJS) $(LDFLAGS) $(OS_LIB_FLAGS) -o $(BIN_DIR)/$@

# link bin file
$(MAIN_TARGET): $(CXX_OBJS)
	@echo "\n\r*** linking '$(MAIN_TARGET)' @='$@' "
	$(CXX) $(CXX_OBJS) $(LDFLAGS) -o $(BIN_DIR)/$@

# make each file
$(OBJ_DIR)/%.o: %.c
	@echo "*** making ^= '$^' @='$@'"
	$(CXX) $(CXXFLAGS) -c $^ -o $@

clean:
	@echo "\n\r*** cleaning up\r\n"
	@echo "$(RM) $(MAIN_TARGET)"
	@echo "$(RM) $(CXX_OBJS)"
	@rm -f $(MAIN_TARGET) $(wildcard *.o)
	@rm -rf $(OBJ_DIR)
	@rm -rf $(BIN_DIR)

