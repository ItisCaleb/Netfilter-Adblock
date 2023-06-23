# Netfilter-Adblocker
using netfilter to block ads hosts

# Usage
Download dependencies
```sh
$ sudo apt-get install libelf-dev gperf clang llvm linux-tools-`uname -r`
```


For userspace program, you need to download libnetfilter first.
```sh
$ sudo apt-get install libnetfilter-dev
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
$ make ssl_sniff
```

The full functionality need both kernel module and bpf program.
If you just want to block host then you can just load module.
The BPF program is to handle TLS connection
```sh
$ make
```

# Update Host Block List
Just append the host you want to block to the file `hosts`

**Make sure there isn't any blank line in your list**
