#!/usr/bin/env bash
set -euo pipefail

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
norm_bool() {
  local value
  value="$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "${value}" in
    1|true|on|yes) echo "true" ;;
    0|false|off|no) echo "false" ;;
    *) echo "${2:-false}" ;;
  esac
}
slugify_target() {
  local input_name
  input_name="$(basename "$1")"
  input_name="${input_name%.*}"
  input_name="$(echo "${input_name}" | tr '[:upper:]' '[:lower:]')"
  input_name="$(echo "${input_name}" | sed -E 's/(_|-)?ipv6(_|-)?(hitlist|test|list)?$//; s/(_|-)?(hitlist|test|list)$//; s/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')"
  if [[ "${input_name}" == "vn" ]]; then
    echo "vietnam"
  elif [[ -n "${input_name}" ]]; then
    echo "${input_name}"
  else
    echo "targets"
  fi
}
resolve_target_input() {
  case "$1" in
    /*|*/*) echo "$1" ;;
    *) echo "input/$1" ;;
  esac
}
resolve_executable() {
  local value="$1"
  shift

  if [[ -n "${value}" ]]; then
    if [[ "${value}" == */* && -x "${value}" ]]; then
      echo "${value}"
      return 0
    fi
    if command -v "${value}" >/dev/null 2>&1; then
      command -v "${value}"
      return 0
    fi
  fi

  local candidate
  for candidate in "$@"; do
    if [[ -x "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  done

  echo "${value}"
}

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PROJECT_DIR}"

if [[ -f "${PROJECT_DIR}/config.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${PROJECT_DIR}/config.env"
  set +a
fi

SHOW_HELP=0
PRINT_CONFIG=0

TARGET_INPUT="${TARGET_INPUT:-input/vietnam_ipv6.txt}"
TARGET_NAME="${TARGET_NAME:-}"
RUN_DATE="${RUN_DATE:-$(date '+%Y-%m-%d')}"
OUTPUT_ROOT="${OUTPUT_ROOT:-output}"

ZMAP_ENABLE="${ZMAP_ENABLE:-true}"
ZDNS_ENABLE="${ZDNS_ENABLE:-true}"
GENERATE_ENABLE="${GENERATE_ENABLE:-true}"
QSCANNER_ENABLE="${QSCANNER_ENABLE:-true}"

PORT="${PORT:-443}"
ZMAP_RATE="${ZMAP_RATE:-1000}"
ZMAP_BIN="${ZMAP_BIN:-/usr/local/sbin/zmap}"
ZMAP_SUDO="${ZMAP_SUDO:-sudo}"
ZMAP_INTERFACE="${ZMAP_INTERFACE:-ens5}"
ZMAP_IPV6_SOURCE_IP="${ZMAP_IPV6_SOURCE_IP:-}"
ZMAP_GATEWAY_MAC="${ZMAP_GATEWAY_MAC:-}"
ZMAP_MODULE="${ZMAP_MODULE:-ipv6_quic_initial}"
ZMAP_PROBE_ARGS="${ZMAP_PROBE_ARGS:-padding:1178}"
ZMAP_DEDUP_METHOD="${ZMAP_DEDUP_METHOD:-none}"
ZMAP_FALLBACK_TO_INPUT="${ZMAP_FALLBACK_TO_INPUT:-true}"

ZDNS_BIN="${ZDNS_BIN:-zdns}"
ZDNS_THREADS="${ZDNS_THREADS:-200}"
ZDNS_SERVERS="${ZDNS_SERVERS:-8.8.8.8,8.8.4.4}"

QSCANNER_BIN="${QSCANNER_BIN:-../ipv4/qscanner}"
QSCANNER_BUCKET_SIZE="${QSCANNER_BUCKET_SIZE:-50}"

for arg in "$@"; do
  case "${arg}" in
    --help|-h) SHOW_HELP=1; shift ;;
    --print-config) PRINT_CONFIG=1; shift ;;
    --input=*) TARGET_INPUT="${arg#*=}"; shift ;;
    --target=*) TARGET_NAME="${arg#*=}"; shift ;;
    --date=*) RUN_DATE="${arg#*=}"; shift ;;
    --output-root=*) OUTPUT_ROOT="${arg#*=}"; shift ;;
    --out-dir=*) OUT_DIR="${arg#*=}"; shift ;;
    --zmap=*) ZMAP_ENABLE="$(norm_bool "${arg#*=}" "${ZMAP_ENABLE}")"; shift ;;
    --zdns=*) ZDNS_ENABLE="$(norm_bool "${arg#*=}" "${ZDNS_ENABLE}")"; shift ;;
    --generate=*) GENERATE_ENABLE="$(norm_bool "${arg#*=}" "${GENERATE_ENABLE}")"; shift ;;
    --qscanner=*) QSCANNER_ENABLE="$(norm_bool "${arg#*=}" "${QSCANNER_ENABLE}")"; shift ;;
    --rate=*) ZMAP_RATE="${arg#*=}"; shift ;;
    --interface=*) ZMAP_INTERFACE="${arg#*=}"; shift ;;
    --source-ip=*) ZMAP_IPV6_SOURCE_IP="${arg#*=}"; shift ;;
    --gateway-mac=*) ZMAP_GATEWAY_MAC="${arg#*=}"; shift ;;
    --zdns-bin=*) ZDNS_BIN="${arg#*=}"; shift ;;
    --bucket-size=*) QSCANNER_BUCKET_SIZE="${arg#*=}"; shift ;;
    *) shift ;;
  esac
done

if [[ "${SHOW_HELP}" -eq 1 ]]; then
  cat <<'EOF'
Usage: scan_all.sh [options]

Options:
  --input=FILE                    IPv6 target file. Bare names resolve under input/
  --target=NAME                   Output target name (default: inferred from input)
  --date=YYYY-MM-DD               Output date tag (default: today)
  --output-root=DIR               Output root directory (default: output)
  --out-dir=DIR                   Explicit output directory, overrides <target>-<date>
  --print-config                  Print resolved config and exit

Stages:
  --zmap=true|false               Enable IPv6 ZMap discovery
  --zdns=true|false               Enable zDNS PTR lookup
  --generate=true|false           Generate QScanner input CSV
  --qscanner=true|false           Run QScanner

Network:
  --rate=N                        ZMap rate
  --interface=IFACE               Network interface
  --source-ip=IPv6                ZMap IPv6 source IP
  --gateway-mac=MAC               Gateway MAC
  --zdns-bin=PATH                 zDNS binary path
  --bucket-size=N                 QScanner bucket size
EOF
  exit 0
fi

TARGET_INPUT="$(resolve_target_input "${TARGET_INPUT}")"
TARGET_NAME="${TARGET_NAME:-$(slugify_target "${TARGET_INPUT}")}"
OUT_DIR_DEFAULT="${OUTPUT_ROOT}/${TARGET_NAME}-${RUN_DATE}"
OUT_DIR="${OUT_DIR:-${OUT_DIR_DEFAULT}}"
RUN_TAG="$(date '+%Y%m%d_%H%M%S')"
if [[ "${EUID}" -eq 0 && "${ZMAP_SUDO}" == "sudo" ]]; then
  ZMAP_SUDO=""
fi
SUDO_HOME=""
if [[ -n "${SUDO_USER:-}" ]]; then
  SUDO_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
fi
ZDNS_BIN="$(resolve_executable \
  "${ZDNS_BIN}" \
  "$HOME/go/bin/zdns" \
  "${SUDO_HOME}/go/bin/zdns" \
  "/home/${SUDO_USER:-}/go/bin/zdns" \
  "/home/trungnt/go/bin/zdns" \
  "/home/ubuntu/go/bin/zdns" \
  "/usr/local/bin/zdns" \
  "/usr/bin/zdns")"

if [[ "${PRINT_CONFIG}" -eq 1 ]]; then
  cat <<EOF
TARGET_NAME=${TARGET_NAME}
TARGET_INPUT=${TARGET_INPUT}
RUN_DATE=${RUN_DATE}
OUTPUT_ROOT=${OUTPUT_ROOT}
OUT_DIR=${OUT_DIR}
ZMAP_BIN=${ZMAP_BIN}
ZMAP_INTERFACE=${ZMAP_INTERFACE}
ZMAP_IPV6_SOURCE_IP=${ZMAP_IPV6_SOURCE_IP}
ZMAP_GATEWAY_MAC=${ZMAP_GATEWAY_MAC}
ZMAP_MODULE=${ZMAP_MODULE}
ZMAP_RATE=${ZMAP_RATE}
ZMAP_DEDUP_METHOD=${ZMAP_DEDUP_METHOD}
ZMAP_FALLBACK_TO_INPUT=${ZMAP_FALLBACK_TO_INPUT}
ZDNS_BIN=${ZDNS_BIN}
QSCANNER_BIN=${QSCANNER_BIN}
EOF
  exit 0
fi

if [[ ! -f "${TARGET_INPUT}" ]]; then
  echo "[ERR] target input not found: ${TARGET_INPUT}"
  exit 2
fi
if [[ "${ZMAP_ENABLE}" == "true" ]]; then
  if [[ -z "${ZMAP_IPV6_SOURCE_IP}" ]]; then echo "[ERR] ZMAP_IPV6_SOURCE_IP is required"; exit 2; fi
  if [[ -z "${ZMAP_GATEWAY_MAC}" ]]; then echo "[ERR] ZMAP_GATEWAY_MAC is required"; exit 2; fi
fi
if [[ "${QSCANNER_ENABLE}" == "true" && ! -x "${QSCANNER_BIN}" ]]; then
  echo "[ERR] qscanner not executable: ${QSCANNER_BIN}"
  exit 127
fi
if [[ "${ZDNS_ENABLE}" == "true" && ! -x "${ZDNS_BIN}" ]]; then
  echo "[ERR] zdns not executable: ${ZDNS_BIN}"
  echo "[HINT] Set ZDNS_BIN=/absolute/path/to/zdns in config.env or pass --zdns-bin=/path/to/zdns"
  exit 127
fi

mkdir -p "${OUT_DIR}/zmap" "${OUT_DIR}/qscanner" "${OUT_DIR}/logs"
LOG_FILE="${OUT_DIR}/scan_${RUN_TAG}.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

log "=== IPv6 QUIC scan pipeline started ==="
log "Target=${TARGET_NAME}, Input=${TARGET_INPUT}, Output=${OUT_DIR}"

RAW_ZMAP="${OUT_DIR}/zmap/zmap_ipv6_quic_responses.csv"
IP_OUT="${OUT_DIR}/zmap/ip_list.txt"
ZDNS_OUT="${OUT_DIR}/zmap/zdns_results.json"
QSCANNER_INPUT="${OUT_DIR}/zmap/test_input.csv"

if [[ "${ZMAP_ENABLE}" == "true" ]]; then
  log "[1/4] Running IPv6 ZMap discovery ..."
  ZMAP_CMD=(
    "${ZMAP_BIN}"
    -i "${ZMAP_INTERFACE}" \
    --ipv6-source-ip="${ZMAP_IPV6_SOURCE_IP}" \
    --gateway-mac="${ZMAP_GATEWAY_MAC}" \
    --ipv6-target-file="${TARGET_INPUT}" \
    -M "${ZMAP_MODULE}" \
    -p "${PORT}" \
    --probe-args="${ZMAP_PROBE_ARGS}" \
    --dedup-method="${ZMAP_DEDUP_METHOD}" \
    --output-module=csv \
    -f saddr \
    --output-filter="" \
    --rate="${ZMAP_RATE}" \
    -o "${RAW_ZMAP}"
  )
  log "[DBG] Executing: ${ZMAP_SUDO:+${ZMAP_SUDO} }${ZMAP_CMD[*]}"
  set +e
  if [[ -n "${ZMAP_SUDO}" ]]; then
    "${ZMAP_SUDO}" "${ZMAP_CMD[@]}"
  else
    "${ZMAP_CMD[@]}"
  fi
  ZMAP_RC=$?
  set -e

  if [[ "${ZMAP_RC}" -ne 0 ]]; then
    if [[ "$(norm_bool "${ZMAP_FALLBACK_TO_INPUT}" "true")" == "true" ]]; then
      log "[WARN] ZMap failed with exit code ${ZMAP_RC}; falling back to target input as QScanner IP list."
      awk 'NF > 0 && $1 !~ /^#/ {gsub(/"/, "", $1); print $1}' "${TARGET_INPUT}" | sort -u > "${IP_OUT}"
    else
      exit "${ZMAP_RC}"
    fi
  else
    awk -F',' 'NR==1 && $1=="saddr"{next} NF > 0 {gsub(/"/, "", $1); if ($1!="") print $1}' "${RAW_ZMAP}" | sort -u > "${IP_OUT}"
  fi
else
  log "[1/4] ZMap disabled."
  if [[ ! -f "${IP_OUT}" ]]; then
    cp "${TARGET_INPUT}" "${IP_OUT}"
  fi
fi

TARGET_COUNT="$(wc -l < "${IP_OUT}" | tr -d ' ')"
log "[1/4] QScanner target count: ${TARGET_COUNT}"
if [[ "${TARGET_COUNT}" -eq 0 ]]; then
  echo "[ERR] ip_list.txt is empty: ${IP_OUT}"
  exit 2
fi

if [[ "${ZDNS_ENABLE}" == "true" ]]; then
  log "[2/4] Running zDNS PTR lookup ..."
  "${ZDNS_BIN}" PTR \
    --input-file "${IP_OUT}" \
    --output-file "${ZDNS_OUT}" \
    --threads "${ZDNS_THREADS}" \
    --name-servers "${ZDNS_SERVERS}"
else
  log "[2/4] zDNS disabled."
  if [[ ! -f "${ZDNS_OUT}" ]]; then : > "${ZDNS_OUT}"; fi
fi

if [[ "${GENERATE_ENABLE}" == "true" ]]; then
  log "[3/4] Generating QScanner input ..."
  python3 -m quic_scanner_ipv6.qscanner_input \
    --ip-list "${IP_OUT}" \
    --zdns-json "${ZDNS_OUT}" \
    --out-csv "${QSCANNER_INPUT}" \
    --port "${PORT}"
else
  log "[3/4] QScanner input generation disabled."
fi

if [[ "${QSCANNER_ENABLE}" == "true" ]]; then
  log "[4/4] Running QScanner ..."
  "${QSCANNER_BIN}" \
    --input "${QSCANNER_INPUT}" \
    --output "${OUT_DIR}/qscanner/output" \
    --bucket-size "${QSCANNER_BUCKET_SIZE}" \
    --keylog
else
  log "[4/4] QScanner disabled."
fi

SUCCESS_COUNT="NA"
ERROR_COUNT="NA"
QINFO="${OUT_DIR}/qscanner/output/quic_connection_info.csv"
if [[ -f "${QINFO}" ]]; then
  ERROR_COUNT="$(awk -F',' 'NR==1{for(i=1;i<=NF;i++) h[$i]=i; next} h["errorMessage"]>0 && length($h["errorMessage"])>0{err++} END{print err+0}' "${QINFO}")"
  SUCCESS_COUNT="$(awk -F',' 'NR==1{for(i=1;i<=NF;i++) h[$i]=i; next} h["errorMessage"]==0 || length($h["errorMessage"])==0{succ++} END{print succ+0}' "${QINFO}")"
fi

SUMMARY_LINE="$(date '+%Y-%m-%d %H:%M:%S') | TARGET=${TARGET_NAME} | INPUT=${TARGET_INPUT} | RUN=${RUN_TAG} | OUT_DIR=${OUT_DIR} | QS_TARGETS=${TARGET_COUNT} | SUCCESS=${SUCCESS_COUNT} | ERRORS=${ERROR_COUNT} | LOG=${LOG_FILE}"
echo "${SUMMARY_LINE}" | tee -a "${OUT_DIR}/scan_history.log"
ln -sfn "${OUT_DIR}" output_latest || true
log "=== IPv6 QUIC scan pipeline finished ==="
