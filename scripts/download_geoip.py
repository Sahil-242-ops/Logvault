"""
Download the offline IP geolocation database (DB-IP "IP to City Lite", CC BY 4.0).

Run once on an internet-connected machine, then copy the geoip/ folder to the
air-gapped host (it is also baked into the Docker image at build time):
    python scripts/download_geoip.py

LogVault reads any MaxMind-format .mmdb in geoip/, so a MaxMind GeoLite2-City.mmdb
can be dropped in instead. Attribution: IP geolocation by DB-IP (https://db-ip.com).
"""
import datetime
import gzip
import os
import shutil
import urllib.error
import urllib.request

GEOIP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "geoip")
OUT = os.path.join(GEOIP_DIR, "dbip-city-lite.mmdb")


def candidate_months():
    today = datetime.date.today().replace(day=1)
    prev = (today - datetime.timedelta(days=1)).replace(day=1)
    return [today.strftime("%Y-%m"), prev.strftime("%Y-%m")]


def main():
    os.makedirs(GEOIP_DIR, exist_ok=True)
    for month in candidate_months():
        url = f"https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz"
        try:
            print(f"Downloading {url} ...")
            tmp = OUT + ".gz"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (LogVault GeoIP updater)"})
            with urllib.request.urlopen(req, timeout=300) as res, open(tmp, "wb") as f:
                shutil.copyfileobj(res, f)
            with gzip.open(tmp, "rb") as src, open(OUT, "wb") as dst:
                shutil.copyfileobj(src, dst)
            os.remove(tmp)
            print(f"Saved {OUT} ({os.path.getsize(OUT) // (1024 * 1024)} MB)")
            return
        except urllib.error.HTTPError as e:
            print(f"  not available ({e.code})")
    raise SystemExit("Could not download DB-IP City Lite; check https://db-ip.com/db/download/ip-to-city-lite")


if __name__ == "__main__":
    main()
