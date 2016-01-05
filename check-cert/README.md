# check-cert

## Description

Check for days on the expiration date of the SSL certificate of DNS-NAME.

## Setting

```
[plugin.checks.ssl-cert]
command = "/path/to/check-cert -d example.com -c 15 -w 30"
```
