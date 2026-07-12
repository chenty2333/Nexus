#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

log=${1:?usage: assert-linux-io-composition.sh OSTD_SERIAL_LOG}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

awk -f "$script_dir/assert-linux-io-composition.awk" "$log" || exit 1
echo 'linux I/O composition serial assertions: PASS domains=7 effects=9 causal_nodes=10 causal_edges=9 credit_classes=8 credit_units=9'
