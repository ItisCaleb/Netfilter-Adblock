# Netfilter-Adblocker
using netfilter to block ads hosts

# Usage
You need to install [gperf](https://www.gnu.org/software/gperf/) first to compile the program

For userspace program, you need to download libnetfilter first.
```sh
$ sudo apt install libnetfilter-dev
$ make user
$ ./adblock
```

To run as kernel module
```sh
$ make kernel
```

For BPF program, you need to download bpftool and clang to compile.
And make sure you have cloned the libbpf submodule
```sh
$ sudo apt get install clang linux-tools-common
$ make ssl_sniff
```

The full functionality need both kernel module and bpf program.
```sh
$ make
```

# Update Host Block List
Just append the host you want to block to the file `hosts`

**Make sure there isn't any blank line in your list**
