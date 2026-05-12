#!/usr/bin/env bash
# ======================================================================
# scan_pipeline.sh - Unified QUIC scan pipeline (ZMap -> zDNS -> QScanner)
# Author: QUIC Hunter (2025) - v5 (union-of-RAW ip_list, allowlist normalization)
# Features:
#  - Uses existing payload file (no auto-generate)
#  - Saves raw + filtered CSV for UDP and TCP
#  - ip_list.txt is ALWAYS the UNION of all IPs from zmap_udp_raw.csv and zmap_tcp_raw.csv
#  - Light normalization of allowlist (non-destructive) to ensure ZMap consumes every entry
#  - HARDENED step 4/5 enrichment to avoid hangs (kill stale procs, restore .bak, remove .tmp,
#    run python unbuffered, cap domains per IP via CLI)
# ======================================================================
set -euo pipefail

# ---------- helpers ----------
norm_bool() {
  local v
  v=$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')
  case "$v" in
    1|true|on|yes) echo "true" ;;
    0|false|off|no) echo "false" ;;
    *) echo "${2:-false}" ;;
  esac
}
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
slugify_target() {
  local input_name
  input_name="$(basename "$1")"
  input_name="${input_name%.*}"
  echo "${input_name}" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/(_|-)?ipv4(_|-)?(test|list)?$//; s/(_|-)?ips?(_|-)?(test|list)?$//; s/(_|-)?(test|list)$//; s/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' \
    | sed -E 's/^$/targets/'
}
resolve_target_input() {
  case "$1" in
    /*|*/*) echo "$1" ;;
    *) echo "input/$1" ;;
  esac
}

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PROJECT_DIR}"

if [[ -f "${PROJECT_DIR}/config.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${PROJECT_DIR}/config.env"
  set +a
fi

# ---------- parse args & env ----------
SHOW_HELP=0
PRINT_CONFIG=0
ZMAP_ENABLE="${ZMAP_ENABLE:-true}"
TCP443_ENABLE="${TCP443_ENABLE:-true}"
ZDNS_ENABLE="${ZDNS_ENABLE:-true}"
GENERATE_ENABLE="${GENERATE_ENABLE:-true}"
ENRICH_ENABLE="${ENRICH_ENABLE:-true}"
QSCANNER_ENABLE="${QSCANNER_ENABLE:-true}"
WORKERS="${WORKERS:-8}"
ZMAP_MODE="${ZMAP_MODE:-quic_vn}" # quic_vn | udp_empty
TARGET_INPUT="${TARGET_INPUT:-${ZMAP_ALLOWLIST_FILE:-}}"
TARGET_NAME="${TARGET_NAME:-}"
RUN_DATE="${RUN_DATE:-$(date '+%Y-%m-%d')}"
OUTPUT_ROOT="${OUTPUT_ROOT:-output}"
DOMAIN_DB="${DOMAIN_DB:-./database/domain_ip.sqlite}"

# Enrichment anti-hang tunables (env override)
ENRICH_MAX_DOMAINS_PER_IP="${ENRICH_MAX_DOMAINS_PER_IP:-300}"
ENRICH_PROGRESS_EVERY="${ENRICH_PROGRESS_EVERY:-1000}"
ENRICH_CACHE_MAX_IPS="${ENRICH_CACHE_MAX_IPS:-20000}"
ENRICH_DB_TIMEOUT="${ENRICH_DB_TIMEOUT:-60}"

for arg in "$@"; do
  case "$arg" in
    --help|-h) SHOW_HELP=1; shift;;
    --print-config) PRINT_CONFIG=1; shift;;
    --zmap=*) ZMAP_ENABLE=$(norm_bool "${arg#*=}" "${ZMAP_ENABLE}"); shift;;
    --tcp443=*) TCP443_ENABLE=$(norm_bool "${arg#*=}" "${TCP443_ENABLE}"); shift;;
    --zdns=*) ZDNS_ENABLE=$(norm_bool "${arg#*=}" "${ZDNS_ENABLE}"); shift;;
    --generate=*) GENERATE_ENABLE=$(norm_bool "${arg#*=}" "${GENERATE_ENABLE}"); shift;;
    --enrich=*) ENRICH_ENABLE=$(norm_bool "${arg#*=}" "${ENRICH_ENABLE}"); shift;;
    --qscanner=*) QSCANNER_ENABLE=$(norm_bool "${arg#*=}" "${QSCANNER_ENABLE}"); shift;;
    --workers=*) WORKERS="${arg#*=}"; shift;;
    --mode=*) ZMAP_MODE="${arg#*=}"; shift;;
    --input=*) TARGET_INPUT="${arg#*=}"; shift;;
    --target=*) TARGET_NAME="${arg#*=}"; shift;;
    --date=*) RUN_DATE="${arg#*=}"; shift;;
    --output-root=*) OUTPUT_ROOT="${arg#*=}"; shift;;
    --out-dir=*) OUT_DIR="${arg#*=}"; shift;;
    --db=*) DOMAIN_DB="${arg#*=}"; shift;;
    --zmap-only)
      ZMAP_ENABLE=true; TCP443_ENABLE=false; ZDNS_ENABLE=false; GENERATE_ENABLE=false; ENRICH_ENABLE=false; QSCANNER_ENABLE=false; shift;;
    --no-zmap) ZMAP_ENABLE=false; shift;;
    --no-tcp443) TCP443_ENABLE=false; shift;;
    --no-zdns) ZDNS_ENABLE=false; shift;;
    --no-generate) GENERATE_ENABLE=false; shift;;
    --no-enrich) ENRICH_ENABLE=false; shift;;
    --no-qscanner) QSCANNER_ENABLE=false; shift;;
    # optional enrichment overrides
    --enrich-max-domains=*) ENRICH_MAX_DOMAINS_PER_IP="${arg#*=}"; shift;;
    --enrich-progress=*) ENRICH_PROGRESS_EVERY="${arg#*=}"; shift;;
    --enrich-cache=*) ENRICH_CACHE_MAX_IPS="${arg#*=}"; shift;;
    --enrich-db-timeout=*) ENRICH_DB_TIMEOUT="${arg#*=}"; shift;;
    *) shift;;
  esac
done

if [[ "$SHOW_HELP" -eq 1 ]]; then
  cat <<'EOF'
Usage: scan_all.sh [options]

Options:
  --input=FILE                    Input target file. Bare names resolve under input/ (example: vietnam_ipv4.txt)
  --target=NAME                   Output target name (default: inferred from input file)
  --date=YYYY-MM-DD               Output date tag (default: today)
  --output-root=DIR               Output root directory (default: output)
  --out-dir=DIR                   Explicit output directory, overrides <target>-<date>
  --db=FILE                       SQLite domain/IP DB (default: ./database/domain_ip.sqlite)
  --print-config                  Print resolved config and exit
  --zmap=true|false               Enable ZMap UDP discovery (default true)
  --tcp443=true|false             Enable ZMap TCP baseline (default true)
  --zdns=true|false               Enable zDNS PTR lookup (default true)
  --generate=true|false           Generate test_input.csv from zDNS (default true)
  --enrich=true|false             Enrich test_input.csv via domain_ip.sqlite (default true)
  --qscanner=true|false           Run QScanner (default true)
  --workers=N                     Fallback lookup threads (default 8)
  --mode=quic_vn|udp_empty        Choose ZMap UDP probe type (default quic_vn)
  --zmap-only                     Run only ZMap (disables TCP/zDNS/generate/enrich/qscanner)
  -h, --help                      Show help

Enrichment anti-hang knobs:
  --enrich-max-domains=N          Cap domains per IP (default 300)
  --enrich-progress=N             Print progress every N input rows (default 1000)
  --enrich-cache=N                LRU cache max IPs (default 20000)
  --enrich-db-timeout=N           SQLite timeout seconds (default 60)

Env overrides:
  TARGET_INPUT                    Input file path or name under input/
  TARGET_NAME                     Output target name
  RUN_DATE                        Output date tag, YYYY-MM-DD
  OUTPUT_ROOT                     Output root directory (default: output)
  OUT_DIR                         Explicit output directory, overrides <target>-<date>
  PORT                            UDP port (default 443)
  ZMAP_RATE                        packets/s (default 3000)
  ZMAP_PAYLOAD_FILE               path to QUIC Initial-VN payload (required for quic_vn mode)
  ZMAP_ALLOWLIST_FILE             Legacy alias for TARGET_INPUT
  DOMAIN_DB                       SQLite domain/IP DB (default: ./database/domain_ip.sqlite)
  ZDNS_BIN                        absolute path to zdns binary
  ZDNS_THREADS                    threads for zDNS (default 200)
  QSCANNER_BIN                    path to qscanner binary (default ./qscanner)
  QSCANNER_BUCKET_SIZE            (default 1)

  ENRICH_MAX_DOMAINS_PER_IP       (default 300)
  ENRICH_PROGRESS_EVERY           (default 1000)
  ENRICH_CACHE_MAX_IPS            (default 20000)
  ENRICH_DB_TIMEOUT               (default 60)
EOF
  exit 0
fi

# ---------- core config ----------
PORT="${PORT:-443}"
ZMAP_RATE="${ZMAP_RATE:-3000}"
ZMAP_FILEMODE="${ZMAP_FILEMODE:-true}"
ZMAP_PAYLOAD_FILE="${ZMAP_PAYLOAD_FILE:-initial_qscanner_1a1a1a1a.pkt}"
TARGET_INPUT="${TARGET_INPUT:-input/vietnam_ipv4.txt}"
TARGET_INPUT="$(resolve_target_input "${TARGET_INPUT}")"
TARGET_NAME="${TARGET_NAME:-$(slugify_target "${TARGET_INPUT}")}"
ZMAP_ALLOWLIST_FILE="${TARGET_INPUT}"
ZDNS_THREADS="${ZDNS_THREADS:-200}"
QSCANNER_BUCKET_SIZE="${QSCANNER_BUCKET_SIZE:-1}"

OUT_DIR_DEFAULT="${OUTPUT_ROOT}/${TARGET_NAME}-${RUN_DATE}"
OUT_DIR="${OUT_DIR:-$OUT_DIR_DEFAULT}"
RUN_TAG="$(date '+%Y%m%d_%H%M%S')"

if [[ "${PRINT_CONFIG}" -eq 1 ]]; then
  cat <<EOF
TARGET_NAME=${TARGET_NAME}
TARGET_INPUT=${TARGET_INPUT}
RUN_DATE=${RUN_DATE}
OUTPUT_ROOT=${OUTPUT_ROOT}
OUT_DIR=${OUT_DIR}
DOMAIN_DB=${DOMAIN_DB}
ZMAP_MODE=${ZMAP_MODE}
PORT=${PORT}
EOF
  exit 0
fi

mkdir -p "${OUT_DIR}/zmap" "${OUT_DIR}/qscanner" "${OUT_DIR}/logs"
LOG_FILE="${OUT_DIR}/scan_${RUN_TAG}.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

log "=== QUIC scan pipeline started ==="
log "Target: ${TARGET_NAME}, Input: ${TARGET_INPUT}"
log "Output: ${OUT_DIR}, Run: ${RUN_TAG}, Port=${PORT}, ZMAP_MODE=${ZMAP_MODE}, TCP443_ENABLE=${TCP443_ENABLE}"
log "ZMAP_RATE=${ZMAP_RATE}"
log "ENRICH_MAX_DOMAINS_PER_IP=${ENRICH_MAX_DOMAINS_PER_IP}, ENRICH_PROGRESS_EVERY=${ENRICH_PROGRESS_EVERY}, ENRICH_CACHE_MAX_IPS=${ENRICH_CACHE_MAX_IPS}"

# ---------- locate binaries ----------
ZMAP_BIN="${ZMAP_BIN:-$(command -v zmap 2>/dev/null || true)}"
if [[ -z "${ZDNS_BIN:-}" ]]; then ZDNS_BIN="$(command -v zdns 2>/dev/null || true)"; fi
if [[ -z "${ZDNS_BIN}" && -x "$HOME/go/bin/zdns" ]]; then ZDNS_BIN="$HOME/go/bin/zdns"; fi
if [[ -z "${ZDNS_BIN}" && -n "${SUDO_USER:-}" ]]; then
  SUDO_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6 || true)"
  if [[ -n "$SUDO_HOME" && -x "$SUDO_HOME/go/bin/zdns" ]]; then
    ZDNS_BIN="$SUDO_HOME/go/bin/zdns"
  fi
fi
QSCANNER_BIN="${QSCANNER_BIN:-./qscanner}"

# sanity checks
if [[ -z "${ZMAP_BIN}" ]]; then echo "[ERR] zmap not found"; exit 127; fi
if [[ ! -x "${QSCANNER_BIN}" ]]; then echo "[ERR] qscanner not executable (${QSCANNER_BIN})"; exit 127; fi
if [[ ! -f "${ZMAP_ALLOWLIST_FILE}" && "${ZMAP_ENABLE}" == "true" ]]; then
  echo "[ERR] allowlist file not found: ${ZMAP_ALLOWLIST_FILE}"; exit 2;
fi
# require payload file for quic_vn
if [[ "${ZMAP_MODE}" == "quic_vn" && "${ZMAP_ENABLE}" == "true" ]]; then
  if [[ ! -f "${ZMAP_PAYLOAD_FILE}" ]]; then
    echo "[ERR] ZMAP_PAYLOAD_FILE not found: ${ZMAP_PAYLOAD_FILE}"
    echo "[HINT] Set env ZMAP_PAYLOAD_FILE to your payload path (e.g., ./initial_qscanner_1a1a1a1a.pkt)"
    exit 2
  fi
fi
if [[ "${ZDNS_ENABLE}" == "true" && ( -z "${ZDNS_BIN}" || ! -x "${ZDNS_BIN}" ) ]]; then
  echo "[ERR] zDNS enabled but zdns binary not found or not executable."
  echo "[DBG] Set ZDNS_BIN=/absolute/path/to/zdns"
  echo "[DBG] ZDNS_BIN='${ZDNS_BIN:-<empty>}', PATH='$PATH', SUDO_USER='${SUDO_USER:-}', HOME='$HOME'"
  exit 127
fi

log "[DBG] Using ZMAP_BIN=${ZMAP_BIN}, ZDNS_BIN=${ZDNS_BIN:-<none>}, QSCANNER_BIN=${QSCANNER_BIN}"
log "[DBG] Using ZMAP_PAYLOAD_FILE=${ZMAP_PAYLOAD_FILE}"

# ======================================================================
# Light normalization of allowlist (non-destructive)
# - remove CR, trim whitespace, remove comments/blank/IPv6 lines
# - collapse internal spaces so CIDR like "1.2.3.0 /24" -> "1.2.3.0/24"
# - deduplicate
# ======================================================================
ALLOW_SRC="${ZMAP_ALLOWLIST_FILE}"
ALLOW_NORM="${OUT_DIR}/zmap/allowlist.normalized.txt"
mkdir -p "${OUT_DIR}/zmap"

awk '
  { gsub("\r","",$0);             # remove CR
    gsub(/^[ \t]+/,"",$0);        # ltrim
    gsub(/[ \t]+$/,"",$0);        # rtrim
    gsub(/[ \t]+/," ",$0);        # collapse multiple spaces to single
    gsub(" /","/",$0);            # remove space before slash in CIDR
  }
  /^[#]/ {next}                   # skip comment
  /^$/  {next}                    # skip empty
  /:/   {next}                    # skip IPv6 (contains colon)
  { print }
' "${ALLOW_SRC}" | sort -u > "${ALLOW_NORM}"

AL_LINES=$(wc -l < "${ALLOW_NORM}" | tr -d " ")
log "[DBG] Allowlist normalized -> ${ALLOW_NORM} (lines=${AL_LINES})"
if [[ "${AL_LINES}" -eq 0 && "${ZMAP_ENABLE}" == "true" ]]; then
  echo "[ERR] Normalized allowlist is empty. Check ${ZMAP_ALLOWLIST_FILE}"; exit 2
fi

# ======================================================================
# 1/5: ZMap UDP (Initial-VN) — save raw + filtered CSV
# ======================================================================
if [[ "${ZMAP_ENABLE}" == "true" ]]; then
  log "[1/5] Running ZMap (stateless discovery) rate=${ZMAP_RATE} pps (${ZMAP_MODE}) ..."
  OUT_UDP_RAW="${OUT_DIR}/zmap/zmap_udp_raw.csv"
  OUT_UDP_FILTERED="${OUT_DIR}/zmap/zmap_udp.csv"

  if [[ "${ZMAP_MODE}" == "quic_vn" ]]; then
    ZMAP_CMD=( "${ZMAP_BIN}" -M udp -p "${PORT}" --output-module=csv \
      -f "saddr,daddr,ipid,ttl,sport,dport,classification,repeat,cooldown,timestamp_ts,timestamp_us,success" \
      --probe-args="file:${ZMAP_PAYLOAD_FILE}" \
      --allowlist-file="${ALLOW_NORM}" \
      -r "${ZMAP_RATE}" \
      --output-filter="" )
    log "[DBG] Executing ZMap UDP Initial-VN (raw): ${ZMAP_CMD[*]}"
    "${ZMAP_CMD[@]}" -o "${OUT_UDP_RAW}"

    if [[ -s "${OUT_UDP_RAW}" ]]; then
      awk -F',' 'NR==1{print; next} ($7 != "icmp" && $12 == "1") {print}' "${OUT_UDP_RAW}" > "${OUT_UDP_FILTERED}"
    else
      : > "${OUT_UDP_FILTERED}"
    fi
  else
    ZMAP_CMD=( "${ZMAP_BIN}" -M udp -p "${PORT}" --output-module=csv \
      -f "saddr,daddr,ipid,ttl,sport,dport,classification,repeat,cooldown,timestamp_ts,timestamp_us,success" \
      --probe-args="hex:00" \
      --allowlist-file="${ALLOW_NORM}" \
      -r "${ZMAP_RATE}" \
      --output-filter="" )
    log "[DBG] Executing ZMap UDP-empty (raw): ${ZMAP_CMD[*]}"
    "${ZMAP_CMD[@]}" -o "${OUT_UDP_RAW}"
    cp "${OUT_UDP_RAW}" "${OUT_UDP_FILTERED}"
  fi

  UDP_RAW_LINES=$(($(wc -l < "${OUT_UDP_RAW}" || echo 0)-1))
  UDP_FILT_LINES=$(($(wc -l < "${OUT_UDP_FILTERED}" || echo 0)-1))
  log "[1/5] ZMap UDP raw rows: ${UDP_RAW_LINES}, filtered kept: ${UDP_FILT_LINES}"
else
  log "[1/5] ZMap UDP disabled"
  # require ip_list.txt later; user must set OUT_DIR to existing run.
fi

# ======================================================================
# 1.5/5: TCP baseline scan (tcp_synscan) — save raw + filtered CSV
# ======================================================================
if [[ "${TCP443_ENABLE}" == "true" ]]; then
  log "[1.5/5] Running ZMap TCP SYN baseline on port 443 ..."
  OUT_TCP_RAW="${OUT_DIR}/zmap/zmap_tcp_raw.csv"
  OUT_TCP_FILTERED="${OUT_DIR}/zmap/zmap_tcp.csv"

  "${ZMAP_BIN}" -M tcp_synscan -p 443 --output-module=csv \
    --output-fields="saddr,success,classification,ipid,ttl" \
    --allowlist-file="${ALLOW_NORM}" \
    -r "${ZMAP_RATE}" \
    --output-filter="" \
    -o "${OUT_TCP_RAW}"

  if [[ -s "${OUT_TCP_RAW}" ]]; then
    awk -F',' 'NR==1{print; next} ($2=="1"){print}' "${OUT_TCP_RAW}" > "${OUT_TCP_FILTERED}"
  else
    : > "${OUT_TCP_FILTERED}"
  fi

  TCP_RAW_LINES=$(($(wc -l < "${OUT_TCP_RAW}" || echo 0)-1))
  TCP_FILT_LINES=$(($(wc -l < "${OUT_TCP_FILTERED}" || echo 0)-1))
  log "[1.5/5] TCP raw rows: ${TCP_RAW_LINES}, filtered kept: ${TCP_FILT_LINES}"
else
  log "[1.5/5] TCP443 baseline disabled"
fi

# ======================================================================
# Build single ip_list.txt = UNION of all IPs from zmap UDP/TCP RAW CSVs
# ======================================================================
RAW_UDP="${OUT_DIR}/zmap/zmap_udp_raw.csv"
RAW_TCP="${OUT_DIR}/zmap/zmap_tcp_raw.csv"
IP_OUT="${OUT_DIR}/zmap/ip_list.txt"

tmp_union="$(mktemp)"
{
  if [[ -s "${RAW_UDP}" ]]; then
    awk -F',' 'NR>1{gsub(/"/,"",$1); if($1!="") print $1}' "${RAW_UDP}"
  fi
  if [[ -s "${RAW_TCP}" ]]; then
    awk -F',' 'NR>1{gsub(/"/,"",$1); if($1!="") print $1}' "${RAW_TCP}"
  fi
} | sort -u > "${tmp_union}"

mkdir -p "$(dirname "${IP_OUT}")"
mv -f "${tmp_union}" "${IP_OUT}" || true

FINAL_COUNT=$(wc -l < "${IP_OUT}" | tr -d ' ')
log "[DBG] Created UNION ip list from RAW: ${IP_OUT} (count=${FINAL_COUNT})"

if [[ "${FINAL_COUNT}" -eq 0 ]]; then
  echo "[ERR] ip_list.txt is empty. Check ZMap outputs in ${OUT_DIR}/zmap/"
  exit 2
fi

# Cleanup intermediate IP list files (best-effort)
log "[DBG] Cleaning up intermediate IP list files, keeping only ip_list.txt and zmap CSVs"
ZMAP_DIR="${OUT_DIR}/zmap"
rm -f "${ZMAP_DIR}/ip_from_udp_raw.txt" \
      "${ZMAP_DIR}/ip_from_tcp_raw.txt" \
      "${ZMAP_DIR}/ip_from_udp_filt.txt" \
      "${ZMAP_DIR}/ip_from_tcp_filt.txt" \
      "${ZMAP_DIR}/ip_list_for_qscanner.txt" 2>/dev/null || true
rm -f "${ZMAP_DIR}/ip_list_vn.txt" "${ZMAP_DIR}/ip_tcp443_open.txt" 2>/dev/null || true

log "[DBG] Cleanup done; remaining files in ${ZMAP_DIR}:"
ls -1 "${ZMAP_DIR}" | sed -e 's/^/  /' || true

# ======================================================================
# 2/5: zDNS PTR (on IP_OUT)
# ======================================================================
if [[ "${ZDNS_ENABLE}" == "true" ]]; then
  log "[2/5] Running zDNS PTR lookup on QScanner targets ..."
  "${ZDNS_BIN}" PTR \
    --input-file "${IP_OUT}" \
    --output-file "${OUT_DIR}/zmap/zdns_results.json" \
    --threads "${ZDNS_THREADS}" \
    --name-servers 8.8.8.8,8.8.4.4
else
  log "[2/5] zDNS disabled."
  if [[ ! -f "${OUT_DIR}/zmap/zdns_results.json" ]]; then echo "[]" > "${OUT_DIR}/zmap/zdns_results.json"; fi
fi

# ======================================================================
# 3/5: Generate QScanner input (ONLY ip_list + zDNS; NO fallback here)
# ======================================================================
if [[ "${GENERATE_ENABLE}" == "true" ]]; then
  log "[3/5] Generating QScanner input CSV (zDNS only) ..."
  python3 -m quic_scanner_ipv4.qscanner_input \
    --ip-list "${IP_OUT}" \
    --zdns-json "${OUT_DIR}/zmap/zdns_results.json" \
    --out-csv "${OUT_DIR}/zmap/test_input.csv" \
    --port "${PORT}" \
    --workers "${WORKERS}"
else
  log "[3/5] Generation disabled."
fi

# ======================================================================
# 4/5: Enrichment (fill missing from database/*)
# ======================================================================
if [[ "${ENRICH_ENABLE}" == "true" ]]; then
  log "[4/5] Enriching test_input.csv (database) ..."

  # --- harden against native segfaults from OpenMP/BLAS/Arrow/etc. ---
  export OMP_NUM_THREADS=1
  export OPENBLAS_NUM_THREADS=1
  export MKL_NUM_THREADS=1
  export VECLIB_MAXIMUM_THREADS=1
  export NUMEXPR_NUM_THREADS=1
  export PYTHONFAULTHANDLER=1
  export PYTHONUNBUFFERED=1

  # optional but useful if it crashes again
  ulimit -c unlimited || true

  # --- recover from partial run: restore .bak and remove .tmp ---
  INCSV="${OUT_DIR}/zmap/test_input.csv"
  if [[ -f "${INCSV}.tmp" ]]; then
    log "[4/5] Found stale ${INCSV}.tmp -> removing"
    rm -f "${INCSV}.tmp" || true
  fi
  if [[ -f "${INCSV}.bak" && ! -f "${INCSV}" ]]; then
    log "[4/5] Found ${INCSV}.bak but missing ${INCSV} -> restoring"
    mv -f "${INCSV}.bak" "${INCSV}"
  fi

  if [[ ! -f "${INCSV}" ]]; then
    echo "[ERR] Missing ${INCSV}. Step 3/5 may have failed."
    exit 2
  fi

  log "[4/5] Enrich params: max_domains=${ENRICH_MAX_DOMAINS_PER_IP}, progress=${ENRICH_PROGRESS_EVERY}, cache=${ENRICH_CACHE_MAX_IPS}, db_timeout=${ENRICH_DB_TIMEOUT}"
  python3 -u -X faulthandler -m quic_scanner_ipv4.domain_enrichment \
    --db "${DOMAIN_DB}" \
    --out-dir "${OUT_DIR}/zmap" \
    --max-domains-per-ip "${ENRICH_MAX_DOMAINS_PER_IP}" \
    --progress-every "${ENRICH_PROGRESS_EVERY}" \
    --cache-max-ips "${ENRICH_CACHE_MAX_IPS}" \
    --db-timeout "${ENRICH_DB_TIMEOUT}"
else
  log "[4/5] Enrichment disabled."
fi

# ======================================================================
# 5/5: QScanner
# ======================================================================
if [[ "${QSCANNER_ENABLE}" == "true" ]]; then
  log "[5/5] Running QScanner ..."
  "${QSCANNER_BIN}" \
    --input "${OUT_DIR}/zmap/test_input.csv" \
    --output "${OUT_DIR}/qscanner/output" \
    --keylog \
    --bucket-size "${QSCANNER_BUCKET_SIZE}"
  log "QScanner finished."
else
  log "[5/5] QScanner disabled."
fi

# ======================================================================
# Summary
# ======================================================================
TOTAL_IPS=$(wc -l < "${IP_OUT}" | tr -d ' ')
SUCCESS_COUNT="NA"; ERROR_COUNT="NA"
ZMAP_BREAKDOWN=""

QINFO="${OUT_DIR}/qscanner/output/quic_connection_info.csv"
if [[ -f "${QINFO}" ]]; then
  ERROR_COUNT=$(awk -F',' '
  NR==1{for(i=1;i<=NF;i++) h[$i]=i; next}
  h["errorMessage"]>0 && length($h["errorMessage"])>0 {err++}
  END{print err+0}' "${QINFO}")

  SUCCESS_COUNT=$(awk -F',' '
  NR==1{
    for(i=1;i<=NF;i++) h[$i]=i
    has_quic=(h["is_quic"]>0)
    has_ver=(h["quicVersion"]>0)
    has_alpn=(h["alpn"]>0)
    has_err=(h["errorMessage"]>0)
    next
  }
  {
    em = (has_err ? $h["errorMessage"] : "")
    ok = 0
    if (has_quic && $h["is_quic"]=="true") ok=1
    else if (has_ver && length($h["quicVersion"])>0) ok=1
    else if (has_alpn && index($h["alpn"],"h3")>0) ok=1
    if (ok && length(em)==0) succ++
  }
  END{print succ+0}' "${QINFO}")
fi

SUMMARY_LINE="$(date '+%Y-%m-%d %H:%M:%S') | TARGET=${TARGET_NAME} | INPUT=${TARGET_INPUT} | RUN=${RUN_TAG} | OUT_DIR=${OUT_DIR} | QS_TARGETS=${TOTAL_IPS} | SUCCESS=${SUCCESS_COUNT} | ERRORS=${ERROR_COUNT}${ZMAP_BREAKDOWN} | LOG=${LOG_FILE}"
echo "${SUMMARY_LINE}" | tee -a "${OUT_DIR}/scan_history.log"
ln -sfn "${OUT_DIR}" "output_latest" || true
log "=== QUIC scan pipeline finished ==="
