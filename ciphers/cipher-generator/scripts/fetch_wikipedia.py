#!/usr/bin/env python3
"""Fetch a batch of random Wikipedia article intros, normalize to A-Z only text,
and save each as its own file in corpora/. Run repeatedly / with higher --target
to collect more sources. Skips very short or disambiguation-ish extracts."""
import json
import re
import sys
import time
import urllib.request
import urllib.parse
import argparse
import os
import hashlib

API = "https://en.wikipedia.org/w/api.php"
UA = "KryptosCipherGeneratorTool/1.0 (educational research tool; contact: doranchak@gmail.com)"
MIN_CHARS = 900   # minimum normalized letters to keep an article as a useful corpus source
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "corpora")

def normalize(text):
    text = text.upper()
    # drop parenthetical IPA/pronunciation guides and citation-ish bracket content
    text = re.sub(r"\[[^\]]*\]", " ", text)
    text = re.sub(r"[^A-Z]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def fetch_batch(grnlimit=20, retries=3):
    params = {
        "action": "query",
        "format": "json",
        "generator": "random",
        "grnnamespace": "0",
        "grnlimit": str(grnlimit),
        "prop": "extracts",
        "explaintext": "1",
        "exintro": "1",
        "exlimit": str(grnlimit),
    }
    url = API + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("query", {}).get("pages", {})
        except Exception as e:
            sys.stderr.write(f"  retry ({e})\n")
            time.sleep(2)
    return {}

def slugify(title):
    s = re.sub(r"[^A-Za-z0-9]+", "_", title).strip("_")
    return s[:40] if s else "article"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=150, help="number of accepted articles to collect")
    ap.add_argument("--batch", type=int, default=20)
    ap.add_argument("--delay", type=float, default=0.4)
    args = ap.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)
    seen_titles = set()
    # avoid re-using titles already present from a prior run
    for fn in os.listdir(OUT_DIR):
        if fn.startswith("wiki_"):
            pass

    accepted = 0
    attempts = 0
    max_attempts = args.target * 6 // args.batch + 20
    existing_count = len([f for f in os.listdir(OUT_DIR) if f.startswith("wiki_")])
    idx = existing_count

    while accepted < args.target and attempts < max_attempts:
        attempts += 1
        pages = fetch_batch(args.batch)
        for pid, page in pages.items():
            title = page.get("title", "")
            extract = page.get("extract", "")
            if not extract or title in seen_titles:
                continue
            seen_titles.add(title)
            low = extract.lower()
            if "may refer to" in low or "may also refer to" in low:
                continue
            norm = normalize(extract)
            if len(norm) < MIN_CHARS:
                continue
            idx += 1
            fname = f"wiki_{idx:04d}_{slugify(title)}.txt"
            with open(os.path.join(OUT_DIR, fname), "w") as f:
                f.write(norm + "\n")
            accepted += 1
            print(f"[{accepted}/{args.target}] {fname}  ({len(norm)} chars)  <- {title}")
            if accepted >= args.target:
                break
        time.sleep(args.delay)

    print(f"Done. Accepted {accepted} articles after {attempts} batch requests.")

if __name__ == "__main__":
    main()
