#!/usr/bin/python3

# -----------------------------------------------------------
# Python client that retrieves a feed from Maltiverse.com
# Stores results in Elastic database under Elastic Common Schema 8.0.0 convention
#
# (C) 2021 Maltiverse
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

import argparse
import json
import re
from collections import defaultdict
from urllib.parse import urlparse
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import requests

ECS_VERSION = "8.0.0"

# in example: 'AS27657 Foo Bar Internet Telcom'
AS_NAME_PATTERN = re.compile(r"^AS(\d+)\s+(.*)$")


parser = argparse.ArgumentParser()

parser.add_argument(
    "--maltiverse_email",
    dest="maltiverse_email",
    required=True,
    help="Specifies Maltiverse email for login. Required",
)
parser.add_argument(
    "--maltiverse_password",
    dest="maltiverse_password",
    required=True,
    help="Specifies Maltiverse password for login. Required",
)
parser.add_argument(
    "--feed",
    dest="maltiverse_feed",
    required=True,
    help="Specifies Maltiverse Feed ID to retrieve. Required",
)
parser.add_argument(
    "--range",
    dest="maltiverse_range",
    default=None,
    help="Specifies Feed time range. Examples now-1h, now-1w, now-1M",
)
parser.add_argument(
    "--range_field",
    dest="maltiverse_range_field",
    default="modification_time",
    help="Specifies the datetime field to apply filtering range ('creation_time'|'modification_time'). Default 'modification_time'",
)
parser.add_argument(
    "--feed-expiration-days",
    dest="maltiverse_feed_expiration_days",
    default=30,
    help="Specifies the default expiration time in days for the indicators of the selected collection. Default '30'",
)
parser.add_argument(
    "--elastic_host",
    dest="elastic_host",
    default="localhost",
    help="Specifies elastic database destination hostname. Default 'localhost'",
)
parser.add_argument(
    "--elastic_port",
    dest="elastic_port",
    default=9200,
    help="Specifies elastic database destination hostname port. Default '9200'",
)
parser.add_argument(
    "--elastic_username",
    dest="elastic_username",
    default=None,
    help="Specifies elastic database username.",
)
parser.add_argument(
    "--elastic_password",
    dest="elastic_password",
    default=None,
    help="Specifies elastic database password.",
)
parser.add_argument(
    "--elastic_index",
    dest="elastic_index",
    default="maltiverse",
    help="Specifies elastic database index.",
)
parser.add_argument(
    "--verbose",
    dest="verbose",
    action="store_true",
    default=False,
    help="Shows extra information during ingestion",
)
parser.add_argument(
    "--delete_old",
    dest="delete_old",
    action="store_true",
    default=True,
    help="Delete old elements after ingestion",
)
arguments = parser.parse_args()

# Script options
script_path = "."
login_obj = {
    "email": arguments.maltiverse_email,
    "password": arguments.maltiverse_password,
}

session = requests.Session()
session.headers = {
    "content-type": "application/json",
    "accept": "application/json",
}

HEADERS = None

# Create elastic connection
es = Elasticsearch(
    [arguments.elastic_host],
    basic_auth=(arguments.elastic_username, arguments.elastic_password),
)


if not es.indices.exists(index=arguments.elastic_index):
    f = open("mappings.json", "r")
    # Reading from file
    mapping = json.loads(f.read())
    es.indices.create(index=arguments.elastic_index, ignore=400, body=mapping)

counter = defaultdict(int)


# Authentication in Maltiverse service
try:
    data_login = requests.post("https://api.maltiverse.com/auth/login", json=login_obj)
    R_JSON = json.loads(data_login.text)
    if "status" in R_JSON and R_JSON["status"] == "success":
        if R_JSON["auth_token"]:
            HEADERS = {"Authorization": "Bearer " + R_JSON["auth_token"]}
        else:
            print("Authentication failed")
            raise SystemExit()
    else:
        print("Authentication failed")
        raise SystemExit()

except requests.exceptions.RequestException as e:
    raise SystemExit(e)

# Retrieving feed information
COLLECTION_URL = "https://api.maltiverse.com/collection/" + arguments.maltiverse_feed
COLL_RESP = requests.get(COLLECTION_URL, headers=HEADERS)
if COLL_RESP.status_code != 200:
    print("Feed does not exist")
    raise SystemExit()
else:
    COLL_OBJ = json.loads(COLL_RESP.text)

# Apply ranges if specified
if arguments.maltiverse_range and arguments.maltiverse_range_field:
    FEED_URL = (
        COLLECTION_URL
        + "/download?range="
        + arguments.maltiverse_range
        + "&range_field="
        + arguments.maltiverse_range_field
    )
else:
    FEED_URL = COLLECTION_URL + "/download"

# Download feed
print("Retrieving feed: " + COLL_OBJ["name"])
DATA = requests.get(FEED_URL, headers=HEADERS)
elements = json.loads(DATA.text)
print("Retrieved elements: " + str(len(elements)))

# Iterate elements in feed
for element in elements:
    # Generating description field
    first_description = True
    description_string = ""

    ecs_obj = {}
    ecs_obj["ecs.version"] = ECS_VERSION
    ecs_obj["event.category"] = "threat"
    ecs_obj["event.type"] = "indicator"
    ecs_obj["event.dataset"] = "ti_maltiverse"

    ecs_obj["threat.indicator.dataset"] = COLL_OBJ["name"]
    ecs_obj["threat.indicator.marking.tlp"] = "White"
    if element.get("tag"):
        ecs_obj["tags"] = element["tag"]

    if element["type"] == "ip":
        ecs_obj["threat.indicator.type"] = "ipv4-addr"
        ecs_obj["threat.indicator.ip"] = element["ip_addr"]
        ecs_obj["threat.indicator.reference"] = (
            "https://maltiverse.com/ip/" + element["ip_addr"]
        )
        if as_name := element.get("as_name"):
            if matched := AS_NAME_PATTERN.match(as_name):
                ecs_obj["threat.indicator.as.number"] = matched.groups()[0]
                ecs_obj["threat.indicator.as.organization.name"] = element.get(
                    "threat.indicator.as.organization.name", matched.groups()[1]
                )
        ecs_obj["threat.indicator.geo.city_name"] = element.get("city")
        ecs_obj["threat.indicator.geo.country_iso_code"] = element.get("country_code")
        if element.get("location"):
            ecs_obj["threat.indicator.geo.location"] = {
                "lon": element["location"]["lon"],
                "lat": element["location"]["lat"],
            }

        for bl in element["blacklist"]:
            expiration_date = datetime.utcnow() - timedelta(
                days=int(COLL_OBJ["range"].replace("now-", "").replace("d", ""))
            )
            last_seen_obj = datetime.strptime(bl.get("last_seen"), "%Y-%m-%d %H:%M:%S")
            diff = last_seen_obj - expiration_date
            diff_seconds = diff.total_seconds()
            if diff_seconds < 0:
                # Skipping entries that are out of time window
                continue

            ecs_obj["threat.indicator.first_seen"] = datetime.strptime(
                bl.get("last_seen"), "%Y-%m-%d %H:%M:%S"
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ecs_obj["threat.indicator.last_seen"] = datetime.strptime(
                bl.get("last_seen"), "%Y-%m-%d %H:%M:%S"
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ecs_obj["@timestamp"] = ecs_obj["threat.indicator.last_seen"]
            ecs_obj["threat.indicator.sightings"] = bl.get("count", 1)
            ecs_obj["threat.indicator.description"] = bl["description"]
            ecs_obj["threat.indicator.provider"] = bl["source"]

            existing_document_id = None
            insert = True
            if arguments.maltiverse_range:
                query = {
                    "constant_score": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {
                                        "term": {
                                            "threat.indicator.ip": element["ip_addr"]
                                        }
                                    },
                                    {
                                        "term": {
                                            "threat.indicator.description.keyword": bl[
                                                "description"
                                            ]
                                        }
                                    },
                                    {
                                        "term": {
                                            "threat.indicator.provider.keyword": bl[
                                                "source"
                                            ]
                                        }
                                    },
                                ]
                            }
                        }
                    }
                }
                response = es.search(index=arguments.elastic_index, query=query)
                if "hits" in response and response["hits"]["total"]["value"] > 0:
                    if response["hits"]["hits"][0]["_source"] == ecs_obj:
                        # We do nothing if the documents is the same
                        insert = False
                    else:
                        existing_document_id = response["hits"]["hits"][0]["_id"]

            if insert:
                res = es.index(
                    index=arguments.elastic_index,
                    document=ecs_obj,
                    id=existing_document_id,
                )
                if res["result"] == "created":
                    counter["ip_created"] += 1
                    if arguments.verbose:
                        print(
                            "Inserted: "
                            + element.get("ip_addr")
                            + " - "
                            + bl["description"]
                            + " - "
                            + bl["source"]
                        )
                if res["result"] == "updated":
                    counter["ip_updated"] += 1
                    if arguments.verbose:
                        print(
                            "Updated: "
                            + element.get("ip_addr")
                            + " - "
                            + bl["description"]
                            + " - "
                            + bl["source"]
                        )
            else:
                counter["ip_skipped"] += 1
                print(
                    "Skipped: "
                    + element.get("ip_addr")
                    + " - "
                    + bl["description"]
                    + " - "
                    + bl["source"]
                )

    if element["type"] == "hostname":
        ecs_obj["threat.indicator.type"] = "domain-name"
        ecs_obj["threat.indicator.url.domain"] = element.get("hostname")
        if element.get("domain"):
            ecs_obj["threat.indicator.url.registered_domain"] = element.get("domain")
        if element.get("tld"):
            ecs_obj["threat.indicator.url.top_level_domain"] = element.get("tld")
        ecs_obj[
            "threat.indicator.reference"
        ] = "https://maltiverse.com/hostname/" + element.get("hostname")
        if as_name := element.get("as_name"):
            if matched := AS_NAME_PATTERN.match(as_name):
                ecs_obj["threat.indicator.as.number"] = matched.groups()[0]
                ecs_obj["threat.indicator.as.organization.name"] = element.get(
                    "threat.indicator.as.organization.name", matched.groups()[1]
                )

        for bl in element["blacklist"]:
            expiration_date = datetime.utcnow() - timedelta(
                days=int(COLL_OBJ["range"].replace("now-", "").replace("d", ""))
            )
            last_seen_obj = datetime.strptime(bl.get("last_seen"), "%Y-%m-%d %H:%M:%S")
            diff = last_seen_obj - expiration_date
            diff_seconds = diff.total_seconds()
            if diff_seconds < 0:
                # Skipping entries that are out of time window
                continue

            ecs_obj["threat.indicator.first_seen"] = datetime.strptime(
                bl.get("first_seen"), "%Y-%m-%d %H:%M:%S"
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ecs_obj["threat.indicator.last_seen"] = datetime.strptime(
                bl.get("last_seen"), "%Y-%m-%d %H:%M:%S"
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ecs_obj["@timestamp"] = ecs_obj["threat.indicator.last_seen"]
            ecs_obj["threat.indicator.sightings"] = bl.get("count", 1)
            ecs_obj["threat.indicator.description"] = bl["description"]
            ecs_obj["threat.indicator.provider"] = bl["source"]

            existing_document_id = None
            insert = True
            if arguments.maltiverse_range:
                query = {
                    "constant_score": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {
                                        "term": {
                                            "threat.indicator.url.domain.keyword": element.get(
                                                "hostname"
                                            )
                                        }
                                    },
                                    {
                                        "term": {
                                            "threat.indicator.description.keyword": bl[
                                                "description"
                                            ]
                                        }
                                    },
                                    {
                                        "term": {
                                            "threat.indicator.provider.keyword": bl[
                                                "source"
                                            ]
                                        }
                                    },
                                ]
                            }
                        }
                    }
                }
                response = es.search(index=arguments.elastic_index, query=query)
                if "hits" in response and response["hits"]["total"]["value"] == 1:
                    if response["hits"]["hits"][0]["_source"] == ecs_obj:
                        # We do nothing if the documents is the same
                        insert = False
                    else:
                        existing_document_id = response["hits"]["hits"][0]["_id"]
                else:
                    if "hits" in response and response["hits"]["total"]["value"] > 1:
                        print(
                            "WARING: "
                            + str(response["hits"]["total"]["value"])
                            + " elements found"
                        )

            if insert:
                res = es.index(
                    index=arguments.elastic_index,
                    document=ecs_obj,
                    id=existing_document_id,
                )
                if res["result"] == "created":
                    counter["hostname_created"] += 1
                    if arguments.verbose:
                        print(
                            "Inserted: "
                            + element.get("hostname")
                            + " - "
                            + bl["description"]
                            + " - "
                            + bl["source"]
                        )
                if res["result"] == "updated":
                    counter["hostname_updated"] += 1
                    if arguments.verbose:
                        print(
                            "Updated: "
                            + element.get("hostname")
                            + " - "
                            + bl["description"]
                            + " - "
                            + bl["source"]
                        )
            else:
                counter["hostname_skipped"] += 1
                print(
                    "Skipped: "
                    + element.get("hostname")
                    + " - "
                    + bl["description"]
                    + " - "
                    + bl["source"]
                )

    if element["type"] == "url":
        ecs_obj["threat.indicator.type"] = "url"
        ecs_obj["threat.indicator.url.full"] = element.get("url")
        ecs_obj["threat.indicator.url.original"] = element.get("url")
        parsed_url = urlparse(element.get("url"))  # prints www.website.com
        if parsed_url.port:
            ecs_obj["threat.indicator.url.port"] = parsed_url.port
        if parsed_url.scheme:
            ecs_obj["threat.indicator.url.scheme"] = parsed_url.scheme
        if element.get("domain"):
            ecs_obj["threat.indicator.url.registered_domain"] = element.get("domain")
        if element.get("tld"):
            ecs_obj["threat.indicator.url.top_level_domain"] = element.get("tld")
        ecs_obj[
            "threat.indicator.reference"
        ] = "https://maltiverse.com/url/" + element.get("urlchecksum")

        for bl in element["blacklist"]:
            expiration_date = datetime.utcnow() - timedelta(
                days=int(COLL_OBJ["range"].replace("now-", "").replace("d", ""))
            )
            last_seen_obj = datetime.strptime(bl.get("last_seen"), "%Y-%m-%d %H:%M:%S")
            diff = last_seen_obj - expiration_date
            diff_seconds = diff.total_seconds()
            if diff_seconds < 0:
                # Skipping entries that are out of time window
                continue

            ecs_obj["threat.indicator.first_seen"] = datetime.strptime(
                bl.get("first_seen"), "%Y-%m-%d %H:%M:%S"
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ecs_obj["threat.indicator.last_seen"] = datetime.strptime(
                bl.get("last_seen"), "%Y-%m-%d %H:%M:%S"
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ecs_obj["@timestamp"] = ecs_obj["threat.indicator.last_seen"]
            ecs_obj["threat.indicator.sightings"] = bl.get("count", 1)
            ecs_obj["threat.indicator.description"] = bl["description"]
            ecs_obj["threat.indicator.provider"] = bl["source"]

            res = es.index(index=arguments.elastic_index, document=ecs_obj)

            existing_document_id = None
            insert = True
            if arguments.maltiverse_range:
                query = {
                    "constant_score": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {
                                        "term": {
                                            "threat.indicator.url.full.keyword": element.get(
                                                "url"
                                            )
                                        }
                                    },
                                    {
                                        "term": {
                                            "threat.indicator.description.keyword": bl[
                                                "description"
                                            ]
                                        }
                                    },
                                    {
                                        "term": {
                                            "threat.indicator.provider.keyword": bl[
                                                "source"
                                            ]
                                        }
                                    },
                                ]
                            }
                        }
                    }
                }
                response = es.search(index=arguments.elastic_index, query=query)
                if "hits" in response and response["hits"]["total"]["value"] == 1:
                    if response["hits"]["hits"][0]["_source"] == ecs_obj:
                        # We do nothing if the documents is the same
                        insert = False
                    else:
                        existing_document_id = response["hits"]["hits"][0]["_id"]
                else:
                    if "hits" in response and response["hits"]["total"]["value"] > 1:
                        insert = False
                        print(
                            "WARING: "
                            + str(response["hits"]["total"]["value"])
                            + " elements found"
                        )

            if insert:
                res = es.index(
                    index=arguments.elastic_index,
                    document=ecs_obj,
                    id=existing_document_id,
                )

                if res["result"] == "created":
                    counter["url_created"] += 1
                    if arguments.verbose:
                        print(
                            "Inserted: "
                            + element.get("url")
                            + " - "
                            + bl["description"]
                            + " - "
                            + bl["source"]
                        )
                if res["result"] == "updated":
                    counter["url_updated"] += 1
                    if arguments.verbose:
                        print(
                            "Updated: "
                            + element.get("url")
                            + " - "
                            + bl["description"]
                            + " - "
                            + bl["source"]
                        )
            else:
                counter["hostname_skipped"] += 1
                print(
                    "Skipped: "
                    + element.get("url")
                    + " - "
                    + bl["description"]
                    + " - "
                    + bl["source"]
                )

    if element["type"] == "sample":
        ecs_obj["threat.indicator.type"] = "file"
        ecs_obj["threat.indicator.file.hash.sha256"] = element.get("sha256")
        if element.get("md5"):
            ecs_obj["threat.indicator.file.hash.md5"] = element.get("md5")
        if element.get("sha512"):
            ecs_obj["threat.indicator.file.hash.sha512"] = element.get("sha512")
        if element.get("filetype"):
            ecs_obj["threat.indicator.file.type"] = element.get("filetype")
        if element.get("size"):
            ecs_obj["threat.indicator.file.size"] = element.get("size")
        if element.get("creation_time"):
            ecs_obj["threat.indicator.first_seen"] = datetime.strptime(
                element.get("creation_time"), "%Y-%m-%d %H:%M:%S"
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if element.get("modification_time"):
            ecs_obj["threat.indicator.last_seen"] = datetime.strptime(
                element.get("modification_time"), "%Y-%m-%d %H:%M:%S"
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ecs_obj["@timestamp"] = ecs_obj["threat.indicator.last_seen"]

        existing_document_id = None
        insert = True
        if arguments.maltiverse_range:
            query = {
                "constant_score": {
                    "filter": {
                        "bool": {
                            "must": [
                                {
                                    "term": {
                                        "threat.indicator.file.hash.sha256": element.get(
                                            "sha256"
                                        )
                                    }
                                },
                            ]
                        }
                    }
                }
            }
            response = es.search(index=arguments.elastic_index, query=query)
            if "hits" in response and response["hits"]["total"]["value"] == 1:
                insert = False
        if insert:
            res = es.index(index=arguments.elastic_index, document=ecs_obj)
            if res["result"] == "created":
                counter["sample_created"] += 1
                if arguments.verbose:
                    print("Inserted: " + element.get("sha256"))
            if res["result"] == "updated":
                counter["sample_updated"] += 1
                if arguments.verbose:
                    print("Updated: " + element.get("sha256"))

if arguments.delete_old:
    query = {
        "bool": {
            "must": [
                {"term": {"threat.indicator.dataset.keyword": COLL_OBJ["name"]}},
                {
                    "range": {
                        "threat.indicator.last_seen": {"lte": COLL_OBJ["range"] + "/d"}
                    }
                },
            ]
        }
    }
    response_delete = es.delete_by_query(
        index=arguments.elastic_index, conflicts="proceed", body={"query": query}
    )
    print("OLD Documents deleted:\t" + str(response_delete["deleted"]))

es.transport.close()

print(
    f"""
###########################################"
PROCESSED:\t\t{COLL_OBJ['name']}
-------------------------------------------
IPs Inserted:\t\t{counter['ip_created']}
IPs Updated:\t\t{counter['ip_updated']}
IPs Skipped:\t\t{counter['ip_skipped']}
-------------------------------------------
Hostnames Inserted:\t{counter['hostname_created']}
Hostnames Updated:\t{counter['hostname_updated']}
Hostnames Skipped:\t{counter['hostname_skipped']}
-------------------------------------------
URLs Inserted:\t\t{counter['url_created']}
URLs Updated:\t\t{counter['url_updated']}
URLs Skipped:\t\t{counter['url_skipped']}
-------------------------------------------
SHA256 Inserted:\t{counter['sample_created']}
SHA256 Updated:\t\t{counter['sample_updated']}
SHA256 Skipped:\t\t{counter['sample_skipped']}
###########################################
"""
)
