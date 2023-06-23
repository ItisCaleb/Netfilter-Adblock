import subprocess

libs = ["libssl.so.3","SSL_write", #OpenSSL
        "libnspr4.so","PR_Write"] #NSS


subprocess.run(["./ssl_sniff"] + libs)