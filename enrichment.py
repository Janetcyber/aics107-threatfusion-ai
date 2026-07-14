"""
threatfusion_ai.enrichment
Lab 8 - Optional Online Metadata Enrichment (URLhaus / OTX)

Design decisions (documented for the capstone report / analyst reflection):

1. Live enrichment is OFF by default and stays off unless BOTH conditions are met:
     - THREATFUSION_LIVE_ENRICHMENT=1 is set in .env
     - a non-empty API key is present for the relevant source
   As of this build, no instructor authorization has been granted for live
   URLhaus/OTX use, so THREATFUSION_LIVE_ENRICHMENT is left at 0 and the
   engine runs exclusively in offline mode. The live client code exists and
   is unit-testable, but is never invoked in this configuration.

2. The pipeline's synthetic IOCs (RFC 5737 documentation-space IPs, .invalid
   domains) are deliberately non-routable and will not resolve on any real
   threat intel feed. A small, clearly-labelled control set of publicly
   documented indicators is used to sanity-check the *client plumbing* only,
   never the corpus data itself, and only when live mode is enabled.

3. Safety: this module only ever queries external services ABOUT an
   indicator (metadata lookup). It never fetches, follows, or downloads
   anything a feed returns. This satisfies the Lab 8 safety notice: "Fetch
   metadata only; do not visit or download anything returned by feeds."

4. API key hygiene: keys are read from environment variables populated by
   .env (which is git-ignored). The enrichment log NEVER writes key values.
   A redact_key() helper is applied to any diagnostic string before logging.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# .env loader (no external dependency - manual KEY=VALUE parser)
# --------------------------------------------------------------------------

def load_env(env_path: str = ".env") -> dict:
    """Read a simple KEY=VALUE .env file into a dict and into os.environ.
    Lines starting with # are comments. Missing file returns {} quietly."""
    values = {}
    p = Path(env_path)
    if not p.exists():
        return values
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        values[key] = val
        os.environ.setdefault(key, val)
    return values


def redact_key(value: Optional[str]) -> str:
    """Never print a real key. Show only whether one is present, and a
    short fingerprint length hint, useful for debugging without leaking."""
    if not value:
        return "<empty>"
    return f"<redacted:{len(value)}chars>"


# --------------------------------------------------------------------------
# On-disk cache (avoids re-querying the same indicator repeatedly)
# --------------------------------------------------------------------------

class EnrichmentCache:
    def __init__(self, cache_dir: str = "cache", ttl_seconds: int = 86400):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds

    def _key_path(self, source: str, indicator: str) -> Path:
        h = hashlib.sha256(f"{source}:{indicator}".encode()).hexdigest()[:24]
        return self.cache_dir / f"{source}_{h}.json"

    def get(self, source: str, indicator: str) -> Optional[dict]:
        path = self._key_path(source, indicator)
        if not path.exists():
            return None
        try:
            record = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        if time.time() - record.get("_cached_at", 0) > self.ttl_seconds:
            return None
        return record.get("data")

    def set(self, source: str, indicator: str, data: dict) -> None:
        path = self._key_path(source, indicator)
        record = {"_cached_at": time.time(), "data": data}
        path.write_text(json.dumps(record, indent=2))


# --------------------------------------------------------------------------
# Live clients (built, testable, but only invoked when explicitly enabled)
# --------------------------------------------------------------------------

class URLhausClient:
    """abuse.ch URLhaus - requires an Auth-Key header as of the mandatory
    authentication rollout. See https://urlhaus.abuse.ch/api/"""

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, auth_key: str):
        self.auth_key = auth_key

    def query_host(self, host: str) -> dict:
        import requests  # imported lazily so offline mode never needs it installed
        resp = requests.post(
            f"{self.BASE_URL}/host/",
            data={"host": host},
            headers={"Auth-Key": self.auth_key},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()


class OTXClient:
    """AlienVault OTX DirectConnect API.
    See https://otx.alienvault.com/api"""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def query_indicator(self, indicator: str, ioc_type: str) -> dict:
        import requests
        type_map = {"ips": "IPv4", "domains": "domain", "hashes": "file"}
        section = type_map.get(ioc_type)
        if not section:
            raise ValueError(f"Unsupported OTX indicator type: {ioc_type}")
        url = f"{self.BASE_URL}/indicators/{section}/{indicator}/general"
        resp = requests.get(url, headers={"X-OTX-API-KEY": self.api_key}, timeout=10)
        resp.raise_for_status()
        return resp.json()


# --------------------------------------------------------------------------
# Result record + engine
# --------------------------------------------------------------------------

@dataclass
class EnrichmentResult:
    report_id: str
    indicator: str
    ioc_type: str
    source: str
    status: str            # "offline_skipped" | "live_hit" | "live_miss" | "error"
    detail: str
    queried_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


class EnrichmentEngine:
    def __init__(self, env_path: str = ".env", cache_dir: str = "cache"):
        self.env = load_env(env_path)
        self.live_enabled = self.env.get("THREATFUSION_LIVE_ENRICHMENT", "0") == "1"
        self.otx_key = self.env.get("OTX_API_KEY", "")
        self.urlhaus_key = self.env.get("URLHAUS_AUTH_KEY", "")
        self.cache = EnrichmentCache(cache_dir)

        self._otx_client = OTXClient(self.otx_key) if self.otx_key else None
        self._urlhaus_client = URLhausClient(self.urlhaus_key) if self.urlhaus_key else None

    def status_banner(self) -> str:
        return (
            "Live enrichment: "
            + ("ENABLED" if self.live_enabled else "DISABLED (offline mode)")
            + f" | OTX key: {redact_key(self.otx_key)}"
            + f" | URLhaus key: {redact_key(self.urlhaus_key)}"
        )

    def enrich_indicator(self, report_id: str, indicator: str, ioc_type: str) -> EnrichmentResult:
        source = "otx" if ioc_type in ("ips", "domains", "hashes") else "unknown"

        if not self.live_enabled:
            return EnrichmentResult(
                report_id=report_id,
                indicator=indicator,
                ioc_type=ioc_type,
                source=source,
                status="offline_skipped",
                detail="Live enrichment disabled: no instructor authorization "
                       "granted for AICS-107 Lab 8 (per lab safety notice). "
                       "Indicator not sent to any external service.",
            )

        cached = self.cache.get(source, indicator)
        if cached is not None:
            return EnrichmentResult(
                report_id=report_id, indicator=indicator, ioc_type=ioc_type,
                source=source, status="live_hit",
                detail=f"Served from cache: {json.dumps(cached)[:200]}",
            )

        try:
            if source == "otx" and self._otx_client:
                data = self._otx_client.query_indicator(indicator, ioc_type)
                self.cache.set(source, indicator, data)
                pulses = data.get("pulse_info", {}).get("count", 0)
                return EnrichmentResult(
                    report_id=report_id, indicator=indicator, ioc_type=ioc_type,
                    source=source, status="live_hit",
                    detail=f"OTX pulse_count={pulses}",
                )
            else:
                return EnrichmentResult(
                    report_id=report_id, indicator=indicator, ioc_type=ioc_type,
                    source=source, status="error",
                    detail="No client configured for this indicator type / no API key present.",
                )
        except Exception as exc:  # noqa: BLE001 - log-and-continue is intended here
            return EnrichmentResult(
                report_id=report_id, indicator=indicator, ioc_type=ioc_type,
                source=source, status="error",
                detail=f"{type(exc).__name__}: {exc}",
            )

    def enrich_report_record(self, record: dict) -> list[EnrichmentResult]:
        report_id = record.get("report_id", "UNKNOWN")
        iocs = record.get("extracted_iocs", {})
        results: list[EnrichmentResult] = []
        for ioc_type in ("ips", "domains", "hashes", "urls"):
            for indicator in iocs.get(ioc_type, []):
                results.append(self.enrich_indicator(report_id, indicator, ioc_type))
        return results


# --------------------------------------------------------------------------
# CLI entry point
# --------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Lab 8 - IOC metadata enrichment")
    parser.add_argument("--input", default="data/processed/extracted_iocs.jsonl")
    parser.add_argument("--output", default="data/processed/enrichment_log.jsonl")
    parser.add_argument("--limit", type=int, default=0, help="0 = process all records")
    args = parser.parse_args()

    engine = EnrichmentEngine()
    print(engine.status_banner())

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"ERROR: input file not found: {in_path}")
        return 1

    lines = in_path.read_text().splitlines()
    if args.limit:
        lines = lines[: args.limit]

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    total_indicators = 0
    status_counts: dict[str, int] = {}

    with out_path.open("w") as out_f:
        for line in lines:
            if not line.strip():
                continue
            record = json.loads(line)
            results = engine.enrich_report_record(record)
            for r in results:
                out_f.write(json.dumps(r.to_dict()) + "\n")
                total_indicators += 1
                status_counts[r.status] = status_counts.get(r.status, 0) + 1

    print(f"Processed {len(lines)} report(s), {total_indicators} indicator(s).")
    print(f"Status breakdown: {status_counts}")
    print(f"Enrichment log written to: {out_path}")
    print("No API key values were written to any log file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
