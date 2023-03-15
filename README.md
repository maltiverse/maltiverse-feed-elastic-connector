# Maltiverse Feed Elastic Connector

Connection script to integrate Maltiverse feeds into a Elastic instance.

Elastic version 7 and 8 are supported by this script

```
usage: maltiverse-feed-elastic-connector.py
    [-h]
    --maltiverse_email MALTIVERSE_EMAIL
    --maltiverse_password MALTIVERSE_PASSWORD
    --feed MALTIVERSE_FEED
    [--range MALTIVERSE_RANGE]
    [--range_field MALTIVERSE_RANGE_FIELD]
    [--feed-expiration-days MALTIVERSE_FEED_EXPIRATION_DAYS]
    [--elastic_host ELASTIC_HOST]
    [--elastic_port ELASTIC_PORT]
    [--elastic_username ELASTIC_USERNAME]
    [--elastic_password ELASTIC_PASSWORD]
    [--elastic_index ELASTIC_INDEX]
    [--verbose]
    [--delete_old]

optional arguments:
  -h, --help            show this help message and exit
  --maltiverse_email MALTIVERSE_EMAIL
                        Specifies Maltiverse email for login. Required
  --maltiverse_password MALTIVERSE_PASSWORD
                        Specifies Maltiverse password for login. Required
  --feed MALTIVERSE_FEED
                        Specifies Maltiverse Feed ID to retrieve. Required
  --range MALTIVERSE_RANGE
                        Specifies Feed time range. Examples now-1h, now-1w, now-1M
  --range_field MALTIVERSE_RANGE_FIELD
                        Specifies the datetime field to apply filtering range ('creation_time'|'modification_time'). Default 'modification_time'
  --feed-expiration-days MALTIVERSE_FEED_EXPIRATION_DAYS
                        Specifies the default expiration time in days for the indicators of the selected collection. Default '30'
  --elastic_host ELASTIC_HOST
                        Specifies elastic database destination hostname. Default 'localhost'
  --elastic_port ELASTIC_PORT
                        Specifies elastic database destination hostname port. Default '9200'
  --elastic_username ELASTIC_USERNAME
                        Specifies elastic database username.
  --elastic_password ELASTIC_PASSWORD
                        Specifies elastic database password.
  --elastic_index ELASTIC_INDEX
                        Specifies elastic database index.
  --verbose             Shows extra information during ingestion
  --delete_old          Delete old elements after ingestion
```

## Example 1 - Retrieve "Command & Controls" feed, full sync
maltiverse-feed-elastic-connector.py  --maltiverse_email EMAIL --maltiverse_password PASSWORD --feed VdhZV34B4jHUXfKt_gDi --elastic_username ELASTIC_USERNAME --elastic_password ELASTIC_PASSWORD

## Example 2 - Retrieve "Command & Controls" feed, sync hour download.
maltiverse-feed-elastic-connector.py  --maltiverse_email EMAIL --maltiverse_password PASSWORD --feed VdhZV34B4jHUXfKt_gDi --elastic_username ELASTIC_USERNAME --elastic_password ELASTIC_PASSWORD --delete_old --range now-1h
