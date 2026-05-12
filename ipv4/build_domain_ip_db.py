import argparse
import csv
import json
import os
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from ipaddress import ip_address

# ---------------- Helpers ----------------

def is_ip(s: str) -> bool:
    try:
        ip_address((s or "").strip())
        return True
    except Exception:
        return False

def norm_domain(d: str) -> str:
    d = (d or "").strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def yield_files(folder: str):
    for root, _, files in os.walk(folder):
        for f in files:
            yield os.path.join(root, f)

# ---------------- SQLite ----------------

DDL_STAGING = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;
PRAGMA cache_size=-200000;

CREATE TABLE IF NOT EXISTS domain_ip_stage (
  domain TEXT NOT NULL,
  ip     TEXT NOT NULL,
  source TEXT,
  first_seen TEXT NOT NULL
);
"""

DDL_MAIN = """
CREATE TABLE IF NOT EXISTS domain_ip (
  domain TEXT NOT NULL,
  ip     TEXT NOT NULL,
  source TEXT,
  first_seen TEXT NOT NULL
);
"""

CREATE_INDEXES = """
CREATE UNIQUE INDEX IF NOT EXISTS uq_domain_ip ON domain_ip(domain, ip);
CREATE INDEX IF NOT EXISTS idx_domain ON domain_ip(domain);
CREATE INDEX IF NOT EXISTS idx_ip ON domain_ip(ip);
"""

INSERT_STAGE = "INSERT INTO domain_ip_stage(domain, ip, source, first_seen) VALUES (?,?,?,?)"
INSERT_MAIN_IGNORE = "INSERT OR IGNORE INTO domain_ip(domain, ip, source, first_seen) VALUES (?,?,?,?)"

def open_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    return conn

def prepare_staging(conn: sqlite3.Connection, recreate_stage: bool = True):
    if recreate_stage:
        conn.executescript("""
            DROP TABLE IF EXISTS domain_ip_stage;
        """)
    conn.executescript(DDL_STAGING)
    conn.commit()

def ensure_main_table(conn: sqlite3.Connection, recreate_main: bool = False):
    if recreate_main:
        conn.executescript("""
            DROP TABLE IF EXISTS domain_ip;
        """)
    conn.executescript(DDL_MAIN)
    conn.commit()

def create_indexes(conn: sqlite3.Connection):
    conn.executescript(CREATE_INDEXES)
    conn.execute("VACUUM;")
    conn.commit()

# ---------------- Parsers ----------------

def parse_txt_like(path: str):
    out = []
    first_seen = now_iso()
    base = os.path.basename(path)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"\s+", line)
            if len(parts) < 2:
                continue
            dom_raw, ip_raw = parts[0], parts[1]
            dom = norm_domain(dom_raw)
            ip = ip_raw.strip()
            if dom and is_ip(ip):
                out.append((dom, ip, base, first_seen))
    return out

def parse_csv(path: str):
    out = []
    first_seen = now_iso()
    base = os.path.basename(path)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            a, b = (row[0] or "").strip(), (row[1] or "").strip()
            if is_ip(b) and a:
                out.append((norm_domain(a), b, base, first_seen))
            elif is_ip(a) and b:
                out.append((norm_domain(b), a, base, first_seen))
    return out

def parse_json_or_jsonl(path: str):
    out = []
    first_seen = now_iso()
    base = os.path.basename(path)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read().strip()
    if not text:
        return out

    if "\n{" in text:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            d = norm_domain(obj.get("domain") or obj.get("hostname") or obj.get("name"))
            ip = (obj.get("ip") or obj.get("address") or "").strip()
            if d and is_ip(ip):
                out.append((d, ip, base, first_seen))
        return out

    try:
        data = json.loads(text)
        if isinstance(data, list):
            for obj in data:
                if not isinstance(obj, dict):
                    continue
                d = norm_domain(obj.get("domain") or obj.get("hostname") or obj.get("name"))
                ip = (obj.get("ip") or obj.get("address") or "").strip()
                if d and is_ip(ip):
                    out.append((d, ip, base, first_seen))
        elif isinstance(data, dict):
            d = norm_domain(data.get("domain") or data.get("hostname") or data.get("name"))
            ip = (data.get("ip") or data.get("address") or "").strip()
            if d and is_ip(ip):
                out.append((d, ip, base, first_seen))
    except Exception:
        pass
    return out

def parse_file(path: str):
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".csv":
            return parse_csv(path)
        elif ext in (".json", ".jsonl"):
            return parse_json_or_jsonl(path)
        else:
            return parse_txt_like(path)
    except Exception as e:
        print(f"[WARN] parse failed {path}: {e}")
        return []

# ---------------- Ingest ----------------

def ingest_stage(conn: sqlite3.Connection, rows, batch=20000):
    if not rows:
        return 0
    cur = conn.cursor()
    cur.execute("BEGIN;")
    total = 0
    for i in range(0, len(rows), batch):
        chunk = rows[i:i+batch]
        cur.executemany(INSERT_STAGE, chunk)
        total += cur.rowcount if cur.rowcount else 0
    conn.commit()
    return total

# ---------------- Main ----------------

def main():
    ap = argparse.ArgumentParser(description="Build SQLite DB from database with staging & dedup (v3)")
    ap.add_argument("--source-dir", required=True, help="Folder containing raw domain-IP files")
    ap.add_argument("--db", required=True, help="Output SQLite file")
    ap.add_argument("--max-workers", type=int, default=4, help="Number of parser threads")
    ap.add_argument("--recreate", action="store_true", help="Drop & rebuild main table from staging")
    args = ap.parse_args()

    conn = open_db(args.db)

    # 1) Prepare staging
    prepare_staging(conn, recreate_stage=True)

    # 2) Scan & parse files
    files = list(yield_files(args.source_dir))
    print(f"[INFO] Found {len(files)} files in {args.source_dir}")

    all_rows = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        fut2f = {ex.submit(parse_file, p): p for p in files}
        for fut in as_completed(fut2f):
            p = fut2f[fut]
            rows = fut.result()
            if rows:
                print(f"  + {os.path.basename(p)}: {len(rows)} rows")
                all_rows.extend(rows)

    print(f"[INFO] Total parsed rows (valid IPs only): {len(all_rows)}")
    inserted = ingest_stage(conn, all_rows)
    print(f"[INFO] Inserted into staging: {inserted}")

    # 3) Build/Update main table
    if args.recreate:
        ensure_main_table(conn, recreate_main=True)
        conn.execute("BEGIN;")
        conn.execute("""
            INSERT INTO domain_ip(domain, ip, source, first_seen)
            SELECT domain, ip, MIN(source), MIN(first_seen)
            FROM domain_ip_stage
            WHERE domain <> '' AND ip <> ''
            GROUP BY domain, ip;
        """)
        conn.commit()
    else:
        ensure_main_table(conn, recreate_main=False)
        conn.execute("BEGIN;")
        cur = conn.cursor()
        cur.execute("""
            SELECT domain, ip, MIN(source), MIN(first_seen)
            FROM domain_ip_stage
            WHERE domain <> '' AND ip <> ''
            GROUP BY domain, ip;
        """)
        rows = cur.fetchall()
        cur2 = conn.cursor()
        cur2.executemany(INSERT_MAIN_IGNORE, rows)
        conn.commit()

    # 4) Indexes
    print("[INFO] Creating indexes ...")
    create_indexes(conn)

    # 5) Stats
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM domain_ip")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT ip) FROM domain_ip")
    ips = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT domain) FROM domain_ip")
    doms = cur.fetchone()[0]
    print(f"[STATS] rows={total} | ips={ips} | domains={doms} | DB={args.db}")

if __name__ == "__main__":
    main()