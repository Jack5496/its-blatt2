#the build target
TARGET = sniffer

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) -o $(TARGET) $(TARGET).c -Wall

clean: 
	$(RM) $(TARGET)
