# the compiler
CC = gcc

#the build target
TARGET = PA1

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) -o $(TARGET) $(TARGET).c

clean: 
	$(RM) $(TARGET)
