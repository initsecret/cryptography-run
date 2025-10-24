# Third-Party Libraries

### `libsodium`

```
wget https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz
tar xf libsodium-1.0.18.tar.gz
cd libsodium-1.0.18
./configure --prefix=$(pwd)/../libsodium-build/
make clean && make check && make install
```

### `XKCP`

```
git clone https://github.com/XKCP/XKCP.git
cd XKCP
git submodule update --init
# on x64
make AVX2/libXKCP.a
# on rpi5
make ARMv8A/libXKCP.a
make ARMv8A/UnitTests
./bin/ARMv8A/UnitTests --all
```

### `ascon-c`

```
git clone https://github.com/ascon/ascon-c.git
cd ascon-c
mkdir build && cd build
cmake ..
cmake . -DALG_LIST="asconaeadxof128"
# on x64 and rpi5
cmake . -DIMPL_LIST="opt64"
cmake . -DCOMPILE_DEFS="-DASCON_INLINE_MODE=0;-DASCON_INLINE_PERM=1"
cmake . -L
cmake --build .
ctest
```

```
# on neon
# FIXME: is this faster than opt64?
cmake . -DIMPL_LIST="neon"
```

### `boringssl`

```
git clone https://github.com/google/boringssl.git
cd boringssl
cmake -B build -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../bssl-march-toolchain.cmake
ninja -C build
cd ..
mkdir boringssl-build
cp -r boringssl/include boringssl-build
mkdir boringssl-build/lib
cp boringssl/build/libcrypto.a boringssl-build/lib/
```

### `cycle-counter`

On Raspberry Pi 5:

```
git clone https://github.com/pornin/cycle-counter.git
cd cyccnt
make
sudo insmod cyccnt.ko
# verify that it is loaded
lsmod | grep cyccnt
```

### `libaegis`

```
git clone https://github.com/aegis-aead/libaegis.git
cd libaegis
zig build -Drelease -Dfavor-performance -Dwith-benchmark
./zig-out/bin/benchmark
```
