CC := gcc
ARM32_CC := arm-linux-gnueabihf-gcc
ARM64_CC := aarch64-linux-gnu-gcc
TARGET := main

all: dynamic_$(TARGET) static_$(TARGET) no_pie_$(TARGET) no_defs_$(TARGET)

dynamic_$(TARGET): main.c
	$(CC) -o ./linux_amd64/$@ $<

static_$(TARGET): main.c
	$(CC) -static -o ./linux_amd64/$@ $<

no_pie_$(TARGET): main.c
	$(CC) -no-pie -o ./linux_amd64/$@ $<

no_defs_$(TARGET): main.c
	$(CC) -fno-stack-protector -no-pie -z execstack -Wl,-z,norelro -o ./linux_amd64/$@ $<

x86: main.c
	$(CC) -m32 -o ./linux_x86/$@ $<

arm32: main.c
	$(ARM32_CC) -o ./linux_arm32/$@ $<

arm64: main.c
	$(ARM64_CC) -o ./linux_arm64/$@ $<
	
clean:
	rm -f dynamic_$(TARGET) static_$(TARGET) no_pie_$(TARGET) no_defs_$(TARGET)
