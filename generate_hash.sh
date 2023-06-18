#/bin/sh

if ! [ -x  "$(command -v gperf)" ];
then
    echo "gperf could not be found" >&2
    echo "Please download it first" >&2
    exit 1
fi

if [ "$#" -ne 1 ] || ! [ -d "$1" ];
then
    echo "Must provide output directory" >&2
    echo "Usage: $0 <output directory>"  >&2
    exit 1
fi

echo '%{' > hosts.gperf
echo '%}' >> hosts.gperf
echo '%%' >> hosts.gperf
cat hosts >> hosts.gperf
echo '%%' >> hosts.gperf
gperf -L ANSI-C hosts.gperf > "$1/host_table.h"
rm hosts.gperf

