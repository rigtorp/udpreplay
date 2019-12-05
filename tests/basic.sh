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
for speed in 0.095 0.500 1.000 1.500 1.900
do
  printf "\- replaying ${TCASE} at (speed / %.1f)x...\n" "${speed}"
  "${TCMD}" ./udpreplay -s ${speed} "${PFILE}" 2>&1 | \
   awk '{print $1}' | sed 's|[0-9]$||' >> "${RESFILE}" &
done
wait
diff -u "${CORRFILE}" "${RESFILE}"
echo "Looks good!"
