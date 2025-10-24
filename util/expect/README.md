# CPU Expectations

On Linux, we use `lscpu` and `cpupower frequency-info --proc`.

On MacOS, we use the following command:
```
sysctl -a | grep -e "^hw." -e "^machdep.cpu" > util/expect/offside_cpu.txt
```
