Offline IP geolocation database folder.

Run `python scripts/download_geoip.py` on an internet-connected machine to fetch
DB-IP IP-to-City Lite (CC BY 4.0, https://db-ip.com), then copy this folder to the
air-gapped host. Any MaxMind-format .mmdb (e.g. GeoLite2-City.mmdb) also works.
The Docker image bakes in whatever .mmdb is here at build time.
