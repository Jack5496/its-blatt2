# the compiler
CC = gcc

#the build target
TARGET = sniffer

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) -o $(TARGET) $(TARGET).c -lssl -lcrypto

clean: 
	$(RM) $(TARGET)
