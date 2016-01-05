# check-cert

## Description

Check for days on the expiration date of the SSL certificate of DNS-NAME.

## Usage

```shell
check-cert [-host=<host>] [-crit=<crit-days>] [-warn=<warn-days>]
```

## Setting

```
[plugin.checks.ssl-cert]
command = "/path/to/check-cert -host=example.com -crit=15 -warn=30"
```
