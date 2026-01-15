# `cryptography.run`: Benchmarking Selected Cryptography Primitives

## Security, or Lack Thereof

This repository and the implementations therein are for benchmarking only and should not be used elsewhere. 

## Usage

#### Dependencies

Requires python3, cmake, ninja, gcc or clang.

See [`./3rdparty/README.md`](./3rdparty/README.md).

#### Building and Testing on x64 and aarch64

```
# do a clean build and run all tests
python3 ./util/run.py --clean
# run only the OCH tests
python3 ./util/run.py --testselect OCH
```

#### Benchmarking on x64 Linux

```
# set up the environment and run the benchmark
python3 ./util/run.py --benchmark
```

If that works, yay!! If not, look at the error messages and read the comments in `./util/run.py`. If you are not comfortable letting that python script run `sudo` commands (to disable turbo boost), then remove them from the script and run them manually.

#### Benchmarking on Raspberry Pi5

Ensure that you installed the `cyccnt` kernel module as instructed in [`./3rdparty/README.md`](./3rdparty/README.md).

```
# set up the environment and run the benchmark
python3 ./util/run.py --benchmark
```

If that works, yay!! If not, look at the error messages and read the comments in `./util/run.py`.

#### Benchmarking on STM32F4 Discovery Board

Now, this is tricky. These instructions are adapted from github.com/mupq/pqm4/ and github.com/pornin/c-fn-dsa/tree/main/bench_cm4

##### Prerequisites

For this you need a [STM32F4DISCOVERY board](https://www.st.com/en/evaluation-tools/stm32f4discovery.html), a USB to Mini-B cable to power and flash the board, and [a USB to TTL Serial Cable](https://www.adafruit.com/product/954) to read the serial output.

I was using Fedora Linux so if you're using a different distribution (or MacOS!), you might have to adapt these instructions.

##### Cross-Compiling to the Board

Install the GNU ARM toolchain from https://developer.arm.com/downloads/-/gnu-rm. (WARNING: Do not use the system packages like `dnf install arm-none-eabi-gcc-cs arm-none-eabi-newlib`, those don't have all the tools.)

I also had to `dnf install ncurses-compat-libs`.

Install libopencm3
```
git clone https://github.com/libopencm3/libopencm3.git
cd libopencm3
make TARGETS='stm32/f4'
```

Compile the program
```
TODO
```

##### Connecting to the Board

Install stlink tools.
```
$ sudo dnf install stlink stlink-devel
```

For the TTL cable, connect the (black) `Ground` pin to `GND`, the (green) TX pin to `PA3`, and (white) `RX` pin to `PA2`. (Ignore the red `Power` pin since the board is powered by the mini-USB.)

Now, plug the mini-USB cable to the board and it should power up.

Once you have connected both the TTL cable and the mini-USB cable to the board, run `lsusb` to check that they are connected.
```
$ lsusb
[...]
Bus 003 Device 007: ID 10c4:ea60 Silicon Labs CP210x UART Bridge
Bus 003 Device 008: ID 0483:374b STMicroelectronics ST-LINK/V2.1
[...]
```

Run `st-info --probe` to check that the board is recognized by st-tools.
```
$ sudo st-info --probe
Found 1 stlink programmers
  version:    V2J37S26
  serial:     06XXXXXXXXXXXXXXXXXXXXXX
  flash:      1048576 (pagesize: 16384)
  sram:       196608
  chipid:     0x413
  dev-type:   STM32F4x5_F4x7
```

List `/dev/serial/by-id/` to find the linux device for the TTL cable. For me, it is `/dev/ttyUSB0`.
```
$ ls -l /dev/serial/by-id/
total 0
lrwxrwxrwx. 1 root root 13 Mar 18 22:23 usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0 -> ../../ttyUSB0
lrwxrwxrwx. 1 root root 13 Mar 18 22:27 usb-STMicroelectronics_STM32_STLink_06XXXXXXXXXXXXXXXXXXXXXX-if02 -> ../../ttyACM0
```

##### Flashing and running on the Board

Start a GDB server on the board on port 4500 in one terminal.
```
st-util --listen_port=4500
```

In a second terminal, configure and read from the serial port
```
$ sudo stty --file=/dev/ttyUSB0 speed 115200 -raw
115200
$ cat /dev/ttyUSB0 
```

In a third terminal, start arm-none-eabi-gdb, connect to the board, load the program, and run it.
```
$ arm-none-eabi-gdb timing.elf
[...]
(gdb) target extended-remote :4500
[...]
(gdb) load
Loading section .text, size 0x18a8c lma 0x8000000
Loading section .ARM.exidx, size 0x8 lma 0x8018a8c
Loading section .data, size 0xc lma 0x8018a94
Start address 0x0800c838, load size 101024
Transfer rate: 20 KB/sec, 9184 bytes/write.
(gdb) run
```

At this point, the second terminal connected to the serial port should start printing output.
```
$ cat /dev/ttyUSB0 
~-----------------------------------------
FLASH_ACR (orig): 00000600
FLASH_ACR (set):  00000000
--------------------------------------------------------
```

---

#### License

This repository incorporates code by various authors under various licenses, see respective files for details.
