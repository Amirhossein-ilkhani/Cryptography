# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11
INCLUDES = -I /usr/local/share/openssl/include
LIBS = -L/usr/local/share/openssl/lib -Wl,-rpath=/usr/local/share/openssl/lib -lssl -lcrypto

# Source files and target executable
SRCS = main.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = prog.out

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LIBS) -o $(TARGET)

.cpp.o:
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
