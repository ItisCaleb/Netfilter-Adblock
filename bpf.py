from bcc import BPF
import re
import subprocess
from hpack import Encoder, Decoder

prog = open('ssl_sniff.bpf.c','r').read()
prog = re.sub(r'#include <bpf/[a-z_]+.h>','',prog)

libssl = subprocess.check_output('ldconfig -p | grep libssl.so',shell=True).decode().strip()
if len(libssl) == 0:
    print("No OpenSSL installed!")
    exit(0)

b = BPF(text=prog)
b.attach_uprobe(name="ssl",sym="SSL_write",fn_name="probe_SSL_write")
b.attach_uprobe(name='/snap/firefox/2356/usr/lib/firefox/libnspr4.so',sym="PR_Write",fn_name="probe_SSL_write")
b.attach_uprobe(name='/lib/x86_64-linux-gnu/libnspr4.so',sym="PR_Write",fn_name="probe_SSL_write")


d = Decoder()
def print_event(cpu, data, size):
    event = b['tls_event'].event(data)
    buf = bytearray(event.buf[:event.len])
    buf = buf.decode("utf-8","replace")
    try:
        print(d.decode(buf))
    except:
        pass
    #if 'GET' in buf[:3]:
    print(f'pid: {event.pid} {event.len}:{buf}')
b['tls_event'].open_perf_buffer(print_event)

while 1:
    b.perf_buffer_poll()