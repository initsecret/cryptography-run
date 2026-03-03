# `cryptography.run`: Benchmarking Selected Cryptography Primitives

Code artifact for _The OCH Authenticated Encryption Scheme_.

> **Warning**: This repository and the implementations therein are for benchmarking only and should not be used elsewhere.

## Dependencies

Requires python3, cmake, ninja, gcc or clang.

See [`./3rdparty/README.md`](./3rdparty/README.md) for third-party library setup.

## Building and Testing

```
# clean build and run all tests
python3 ./util/run.py --clean
# run only the OCH tests
python3 ./util/run.py --testselect OCH
```

## Benchmarking on x64 Linux

```
python3 ./util/run.py --benchmark
```

The script uses `sudo` to disable turbo boost. If you prefer, remove those commands from `./util/run.py` and run them manually. See comments in the script for details.

## Benchmarking on Raspberry Pi 5

Install the `cyccnt` kernel module first (see [`./3rdparty/README.md`](./3rdparty/README.md)), then:

```
python3 ./util/run.py --benchmark
```

## License

This repository incorporates code by various authors under various licenses; see respective files for details.
