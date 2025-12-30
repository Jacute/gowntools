CC := gcc
TARGET := main

all: dynamic_$(TARGET) static_$(TARGET) no_pie_$(TARGET)

dynamic_$(TARGET): main.c
	$(CC) -o $@ $<

static_$(TARGET): main.c
	$(CC) -static -o $@ $<

no_pie_$(TARGET): main.c
	$(CC) -no-pie -o $@ $<

clean:
	rm -f dynamic_$(TARGET) static_$(TARGET)
