

test.bin: test.elf
	../binutils-2.43/binutils/objcopy -O binary -S test.elf test.bin

test.elf: boot.o main.o
	../binutils-2.43/ld/ld-new boot.o main.o -Tlinks.ld -o test.elf

boot.o: boot.c
	gcc -E boot.c -o boot.i

	../binutils-2.43/gas/as-new boot.i -o boot.o

main.o: main.c
	clang --target=sparc-none-eabi -mcpu=v8 -mfloat-abi=hard -S main.c -o main.i
	../binutils-2.43/gas/as-new main.i -o main.o

all: test.bin

clean:
	rm -rf *.o *.i *.bin *.elf 
