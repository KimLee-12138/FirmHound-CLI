# FirmRec raw artifact dumps (real runs)

This directory holds the real FirmRec products after a successful run on the
student machine (8/31 full-reproduction day):

  * `VULNS.md`            -- the detection report per firmware
  * `pg_*.csv`            -- PostgreSQL table dumps exported via
                            `docker exec <container> psql -c "COPY ... TO STDOUT WITH CSV HEADER"`
  * `poc_info/`          -- sanitized PoC payloads

These are **not** committed from this host: Docker file-sharing is broken here
(F-FirmRec.md §9) and the base image has not been pulled. Populate this directory
on the run host, then point `scripts/run_external.py --tool firmrec` at the run so
the parser fixtures (in the sibling directories) stay decoupled from the real,
possibly sensitive, output.
