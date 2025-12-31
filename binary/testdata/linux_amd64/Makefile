CC := gcc
TARGET := main

all: dynamic_$(TARGET) static_$(TARGET) no_pie_$(TARGET) no_defs_$(TARGET) partial_relro_$(TARGET)

dynamic_$(TARGET): main.c
	$(CC) -o $@ $<

static_$(TARGET): main.c
	$(CC) -static -o $@ $<

no_pie_$(TARGET): main.c
	$(CC) -no-pie -o $@ $<

no_defs_$(TARGET): main.c
	$(CC) -fno-stack-protector -no-pie -z execstack -Wl,-z,norelro -o $@ $<

partial_relro_$(TARGET): main.c
	$(CC) -Wl,-z,relro -o $@ $<
	
clean:
	rm -f dynamic_$(TARGET) static_$(TARGET) no_pie_$(TARGET) no_defs_$(TARGET) partial_relro_$(TARGET)
