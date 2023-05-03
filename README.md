# cloudvulndb-to-csv

[![CI-build](https://github.com/jochenvanwylick/cloudvulndb-to-csv/actions/workflows/ci-build.yml/badge.svg)](https://github.com/jochenvanwylick/cloudvulndb-to-csv/actions/workflows/ci-build.yml)

Downloads the vulnerabilities reported in [https://www.cloudvulndb.org/](https://www.cloudvulndb.org/) and stores them as CSV, intended for trend analysis.

## Download & Run

  1. Download [latest release](https://github.com/jochenvanwylick/cloudvulndb-to-csv/releases) into writable folder
  2. Run `cloudvulndb-to-csv.exe`

Output should look like:

```
D:\_CODE\cve-db-to-csv\src>cloudvulndb-to-csv.exe
2023/04/20 10:48:44 Cloned openvdb repository https://github.com/wiz-sec/open-cvdb into tmp/data
2023/04/20 10:48:44 Parsed 121 vulnerabilities from tmp/data/vulnerabilities
2023/04/20 10:48:44 Stored vulnerabilities as csv to 20230420_vulnerabilities.csv (D:\_CODE\cve-db-to-csv\src\20230420_vulnerabilities.csv)
2023/04/20 10:48:44 Cleaning up ... removing tmp folder: tmp/data
2023/04/20 10:48:44 All done!
```

## Thanks

Thanks for the folks over at [https://www.cloudvulndb.org/](https://www.cloudvulndb.org/) and its contributors, for maintaining this database and website.