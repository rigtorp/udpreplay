#!/bin/sh

set -e

_TCMD="/usr/bin/time"

linux_time()
{
  "${_TCMD}" -f "\t%e real\t%U user\t%s sys" "${@}"
}

if "${_TCMD}" -f "" echo 2>/dev/null >/dev/null
then
  TCMD="linux_time"
else
  TCMD="${_TCMD}"
fi
  
TCASE="basic_lowres"
TFNAME="${TCASE}.timings"
RESFILE="${TFNAME}"
CORRFILE="../tests/${TFNAME}"
PFILE="../tests/${TCASE}.pcap"

rm -f "${RESFILE}"
for speed in 0.1 0.5 1.0 1.5 1.9
do
  echo "- replaying ${TCASE} at (speed / ${speed})x..."
  "${TCMD}" ./udpreplay -s ${speed} "${PFILE}" 2>&1 | \
   awk '{print $1}' | sed 's|[0-9]$||' >> "${RESFILE}"
done
diff -u "${CORRFILE}" "${RESFILE}"
echo "Looks good!"
