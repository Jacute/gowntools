CC := gcc
CFLAGS := -fno-stack-protector -no-pie -O0

TARGET := main

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
