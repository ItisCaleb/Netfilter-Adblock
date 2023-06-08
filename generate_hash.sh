#/bin/sh

if ! command -v gperf &> /dev/null
then
    echo "gperf could not be found"
    exit
fi

if [ "$#" -ne 1 ] || ! [ -d "$1" ];
then
    echo "must provide output directory"
    echo "usage: $0 <output directory>"
    exit
fi

echo $'%{\n%}\n%%' > hosts.gperf
cat hosts >> hosts.gperf
echo $'\n%%' >> hosts.gperf
gperf -L KR-C hosts.gperf > "$1/host_table.h"
rm hosts.gperf