CXX = g++-13
CC := $(CXX)
TARGET := prog.out
LDFLAGS := -L /opt/openssl/lib
LDLIBS := -lssl -lcrypto
CPPFLAGS :=  -std=c++11 -I /opt/openssl/include
# SRC_DIR := .../src
OBJ_DIR := .
# SRC_FILES := $(wildcard $(SRC_DIR)/*.cpp)
# OBJ_FILES := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC_FILES))

# $(wildcard *.cpp) $(wildcard */*.cpp): get all .cpp files from the current directory and dir "/xxx/xxx/"
SRCS = $(wildcard *.cpp)
# SRCS += $(wildcard **/*.cpp)
# $(patsubst %.cpp,%.o,$(SRCS)): substitute all ".cpp" file name strings to ".o" file name strings
OBJS := $(patsubst %.cpp,%.o,$(SRCS))

.PHONY:all
all: clean build rm_o run 

.PHONY: build
build: $(TARGET)
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(LDLIBS) -o $@ $^
%.o: %.cpp
	$(CC) $(CPPFLAGS) -o $@ -c $<
.PHONY: run
run: prog.out
	./prog.out > out.txt

clean:
	rm -rf $(TARGET)
	rm -rf *.o

rm_o:
	rm -rf *.o
