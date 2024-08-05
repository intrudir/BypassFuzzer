#!/usr/bin/env python3

import sys
import os
import argparse
import requests

from core import funcs
from core.fuzzer.fuzzer import BypassFuzzer
from core.http_reqs.http_req import HTTPRequestReader


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOADS_DIR = f"{SCRIPT_DIR}/core/payloads"
HDR_PAYLOADS_TEMPLATE = f"{PAYLOADS_DIR}/header_payload_templates.txt"
IP_PAYLOADS_FILE = f"{PAYLOADS_DIR}/ip_payloads.txt"
URL_PAYLOADS_FILE = f"{PAYLOADS_DIR}/url_payloads.txt"
DB_DIR = f"{SCRIPT_DIR}/interactions"

# Load banner
with open(f"{SCRIPT_DIR}/core/banner.txt", "r", encoding="UTF-8") as inf:
    BANNER = inf.read()

print(BANNER)

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(
    description="use this script to fuzz endpoints that return a 401/403"
)

# Input & request params
parser.add_argument(
    "-u", "--url", action="store", default=None, dest="url",
    help="Specify the target URL",
)
parser.add_argument(
    "-hv", "--http-vers", action="store", default="HTTP/1.1", dest="http_vers",
    help="Specify the HTTP version e.g. 'HTTP/1.1', 'HTTP/2', etc",
)
parser.add_argument(
    "--scheme", action="store", default="https", dest="http_scheme",
    help="Specify the URL scheme e.g. 'https', 'http', etc. Defaults to https.",
)
parser.add_argument(
    "-m", "--method", action="store", default="GET", dest="method", 
    choices=("GET", "POST", "PUT", "PATCH", "DELETE"),
    help="Specify the HTTP method/verb",
)
parser.add_argument(
    "-d", "--data", action="store", default={}, dest="data_params",
    help="Specify data to send with the request.",
)
parser.add_argument(
    "-c", "--cookies", action="store", default=None, dest="cookies",
    help='Specify cookies to use in requests. \
         (e.g., --cookies "cookie1=blah; cookie2=blah")',
)
parser.add_argument(
    "-H", "--header", action="append", default=None, dest="header",
    help='Add headers to your request\
         (e.g., --header "Accept: application/json" --header "Host: example.com"',
)
parser.add_argument(
    "-r", "--request", action="store", default=None, dest="request", 
    help="Load a text file with a HTTP request in it for fuzzing\
         (e.g., --request req.txt",
)
parser.add_argument(
    "-p", "--proxy", action="store", default={}, dest="proxy", 
    help="Specify a proxy to use for requests \
        (e.g., http://127.0.0.1:8080)",
)

# filtering
parser.add_argument(
    "-hc", action="store", default=None, dest="hc", 
    help="Hide response code from output, single or comma separated",
)
parser.add_argument(
    "-hl", action="store", default=None, dest="hl", 
    help="Hide response length from output, single or comma separated",
)
parser.add_argument(
    "-sf", "--smart", action="store_true", default=False, dest="smart_filter", 
    help="Enable the smart filter",
)

# Skip attacks
parser.add_argument(
    "-sh", "--skip-headers", action="store_true", default=False, dest="skip_headers", 
    help="Skip testing bypass headers",
)
parser.add_argument(
    "-su", "--skip-urls", action="store_true", default=False, dest="skip_urls", 
    help="Skip testing path payloads",
)
parser.add_argument(
    "-std", "--skip-td", action="store_true", default=False, dest="skip_td", 
    help="Skip testing trailing dot attack",
)
parser.add_argument(
    "-sm", "--skip-method", action="store_true", default=False, dest="skip_method", 
    help="Skip testing verb attacks",
)
parser.add_argument(
    "-sp", "--skip-protocol", action="store_true", default=False, dest="skip_protocol", 
    help="Skip testing HTTP protocol attacks",
)

# interaction handling
parser.add_argument(
    "--idb", type=str, default=None, dest="interaction_db", 
    help="The database to display interactions from."
)
parser.add_argument(
    "--save-interactions", type=int, nargs='*', default=[200], dest="save_interactions", 
    help="Save interactions matching criteria to a sqlite3 database for easy querying."
)
parser.add_argument(
    "-di", "--display-interaction", "--display-interactions", type=str, default=None, dest="display_interactions",
    help="Display a specific interaction by index or payload."
)
parser.add_argument(
    "--display-by", type=str, choices=[None, 'index', 'payload'], default=None, 
    dest="display_by", help="The method to identify the interaction to display."
)

# misc
parser.add_argument(
    "--oob", action="store", default=None, dest="oob_payload", 
    help="Specify an OOB server like collaborator or ISH. You must keep an eye on your polling server yourself.",
)
args = parser.parse_args()

if len(sys.argv) <= 1:
    parser.print_help()
    print()
    sys.exit()

# if proxy, set it for requests
proxies = {}
if args.proxy:
    if "http://" in args.proxy or "https://" in args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
    else:
        print(f"You specified an invalid proxy: {args.proxy}")
        print("Don't forget to include the schema (http|https)")
        exit(1)

# get response codes and lengths to hide from result
hide = {"codes": [], "lengths": []}
if args.hc:
    for i in args.hc.split(","):
        hide["codes"].append(i)
if args.hl:
    for i in args.hl.split(","):
        hide["lengths"].append(i)

if args.smart_filter and (args.hc or args.hl):
    print("Can't do smart filter together with hide code or hide length yet")
    sys.exit(1)

# read a text file with a request in it
if args.request:
    print("Request file specified.")

    with open(args.request, encoding="UTF-8") as inf:
        raw_http_request = inf.read()

    RAW_REQ = HTTPRequestReader(raw_http_request, args.http_scheme)

    # Grab various pieces of the req
    url = RAW_REQ.url
    req_method = RAW_REQ.command
    endpoint = RAW_REQ.path
    http_vers = RAW_REQ.request_version
    headers = RAW_REQ.headers
    cookies = RAW_REQ.cookies
    body_data = RAW_REQ.data

else:
    # If we're not using a request from a file, we are using the URL from the -u flag.
    # https://example.com/test/test2?p1=1&p2=2
    req_method = args.method
    url = args.url
    http_vers = args.http_vers
    cookies = funcs.parse_cookies(args.cookies) if args.cookies else {}
    body_data = args.data_params

    # if headers are specified, parse them
    if args.header:
        # If header specified is a text file, read it and get headers out of it.
        if ".txt" in args.header:
            with open(args.header, "r", encoding="UTF-8") as f:
                new_headers = f.read().splitlines()
        else:
            new_headers = args.header

        headers = funcs.parse_headers(new_headers)
    else:
        # Use the defaults from parse_headers
        headers = funcs.parse_headers("")

if __name__ == "__main__":
    # Does the user want to view previous interactions?
    # Both args must be set
    if args.display_interactions is not None or args.display_by is not None:
        if args.display_by is None:
            print("You must specify a method to identify the interaction to display.")
            sys.exit(1)
        if args.display_interactions is None:
            print("You must specify the interaction to display.")
            sys.exit(1)

        try:
            if args.display_by == 'index':
                BypassFuzzer.display_interaction(int(args.display_interactions), args.display_by, DB_DIR, db_name=args.interaction_db)
            else:
                BypassFuzzer.display_interaction(args.display_interactions, args.display_by, DB_DIR, db_name=args.interaction_db)
        except FileNotFoundError:
            if args.interaction_db is None:
                print("No database file was specified or your db dir is empty.")
            else:
                print(f"The database file {args.interaction_db} could not be found.")
            sys.exit(1)
        
        sys.exit(0)

    # Set up the fuzzer for attack
    Fuzzer = BypassFuzzer(
        url, proxies, args.smart_filter, hide,
        URL_PAYLOADS_FILE, HDR_PAYLOADS_TEMPLATE,
        IP_PAYLOADS_FILE, DB_DIR, args.oob_payload, args.save_interactions,
        db_name=args.interaction_db)


    if not args.skip_headers:
        og_headers = headers.copy()
        Fuzzer.header_attack(req_method, http_vers, headers, body_data, cookies)
        if headers != og_headers:
            headers = og_headers.copy()  # reset back to OG headers

    if not args.skip_urls:
        Fuzzer.trail_slash(req_method, http_vers, headers, body_data, cookies)
        Fuzzer.path_attack(req_method, http_vers, headers, body_data, cookies)

    if not args.skip_td:
        # Try sending with absolute domain (trailing dot).
        # If proxy flag is set, skip this. Burp has issues processing
        # domains with the trailing dot and will freak out about illegal SSL.

        if not args.proxy:
            og_host = headers.get("Host")
            Fuzzer.trailing_dot_attack(
                req_method, http_vers, headers, body_data, cookies
            )
            if headers.get("Host") != og_host:
                headers["Host"] = og_host
        else:
            print("\nProxy flag was detected. Skipping trailing dot attack...")

    if not args.skip_method:
        Fuzzer.verb_attack(req_method, http_vers, headers, body_data, cookies)

    if not args.skip_protocol:
        Fuzzer.http_proto_attack(req_method, headers, body_data, cookies)
