CC := gcc
CFLAGS := -no-pie -O0 -g

TARGET := main

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
