#!/usr/bin/env python3

import sys 
import os 
import argparse
import requests

from urllib.parse import urlparse, urlunparse
from time import sleep

from core.functions import *
from core.fuzzer.fuzzer import Bypass_Fuzzer
from core.http_reqs.http_req import HTTPRequestReader


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOADS_DIR = f"{SCRIPT_DIR}/core/payloads"
HDR_PAYLOADS_TEMPLATE = f"{PAYLOADS_DIR}/header_payload_templates.txt"
IP_PAYLOADS_FILE = f"{PAYLOADS_DIR}/ip_payloads.txt"
URL_PAYLOADS_FILE = f"{PAYLOADS_DIR}/url_payloads.txt"

# Load banner
with open(f'{SCRIPT_DIR}/core/banner.txt', 'r') as inf:
    BANNER = inf.read()

print(BANNER)

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(
    description="use this script to fuzz endpoints that return a 401/403")

# Input & request params
parser.add_argument(
    '-u', '--url', action="store", default=None, dest='url',
    help="Specify the target URL")
parser.add_argument(
    '-m', '--method', action="store", default='GET', dest='method',
    choices=('GET', 'POST', 'PUT', 'PATCH', 'DELETE'),
    help="Specify the HTTP method/verb")
parser.add_argument(
     '-d', '--data', action="store", default=None, dest='data_params',
     help="Specify data to send with the request.")
parser.add_argument(
     '-c', '--cookies', action="store", default=None, dest='cookies',
     help="Specify cookies to use in requests. \
         (e.g., --cookies \"cookie1=blah; cookie2=blah\")")
parser.add_argument(
     '-H', '--header', action="append", default=None, dest='header',
     help="Add headers to your request\
         (e.g., --header \"Accept: application/json\" --header \"Host: example.com\"")
parser.add_argument(
     '-r', '--request', action="store", default=None, dest='request',
     help="Load a text file with a HTTP request in it for fuzzing\
         (e.g., --request req.txt")
parser.add_argument(
    '-p', '--proxy', action="store", default={}, dest='proxy',
    help="Specify a proxy to use for requests \
        (e.g., http://127.0.0.1:8080)")

# filtering
parser.add_argument(
    '-hc', action="store", default=None, dest='hc',
    help="Hide response code from output, single or comma separated")
parser.add_argument(
    '-hl', action="store", default=None, dest='hl',
    help="Hide response length from output, single or comma separated")
parser.add_argument(
    '-sf', '--smart', action="store_true", default=False, dest='smart_filter',
    help="Enable the smart filter")

# Skip attacks
parser.add_argument(
    '-sh', '--skip-headers', action="store_true", default=False, dest='skip_headers',
    help="Skip testing bypass headers")
parser.add_argument(
    '-su', '--skip-urls', action="store_true", default=False, dest='skip_urls',
    help="Skip testing path payloads")
parser.add_argument(
    '-std', '--skip-td', action="store_true", default=False, dest='skip_td',
    help="Skip testing trailing dot attack")
parser.add_argument(
    '-sm', '--skip-method', action="store_true", default=False, dest='skip_method',
    help="Skip testing verb attacks")

# misc
parser.add_argument(
    '--export-endpoints', action="store", default=None, dest='export_endpoints',
    help="Saves endpoints with payloads to a file")

args = parser.parse_args()


if len(sys.argv) <= 1:
    parser.print_help()
    print()
    sys.exit()

if args.smart_filter and (args.hc or args.hl):
    print("Can't do smart filter together with hide code or hide length yet")
    sys.exit(1)

# if proxy, set it for requests
proxies = {}
if args.proxy:
    if 'http://' in args.proxy or 'https://' in args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
    else:
        print(f"You specified an invalid proxy: {args.proxy}")
        print("Don't forget to include the schema (http|https)")
        exit(1)
    
# get response codes and lengths to hide from result
hide = {"codes": [], "lengths": []}
if args.hc:
    for i in args.hc.split(','):
        hide["codes"].append(i)
if args.hl:
    for i in args.hl.split(','):
        hide["lengths"].append(i)

# read a text file with a request in it
if args.request:
    print("Request file specified.")
    print("The endpoint path specified in the file will overwrite the endpoint path you specify with (-u, --url).")
    print("Sleeping 5 seconds...")
    sleep(5)

    with open(args.request) as inf:  
        raw_http_request = inf.read()
    
    RAW_REQ = HTTPRequestReader(raw_http_request)

    # Grab various pieces of the req
    req_method = RAW_REQ.command
    endpoint = RAW_REQ.path
    http_proto = RAW_REQ.request_version
    headers = RAW_REQ.headers
    cookies = RAW_REQ.cookies
    body_data = RAW_REQ.data

    # # The endpoint path in the request file should overwrite what we have in -u, --url flag.
    parsed = urlparse(args.url)
    parsed = parsed._replace(query="")
    parsed = parsed._replace(fragment="")
    parsed = parsed._replace(path=endpoint)
    url = urlunparse(parsed)

else:
    # If we're not using a request from a file, we are using the URL from the -u flag.
    # https://example.com/test/test2?p1=1&p2=2
    req_method = args.method
    url = args.url
    cookies = parse_cookies(args.cookies) if args.cookies else {}
    body_data = args.data_params if args.data_params else {}

    # if headers are specified, parse them
    if args.header:
        # If header specified is a text file, read it and get headers out of it.
        if '.txt' in args.header:
            with open(args.header, 'r') as f:  
                new_headers = f.read().splitlines()
        else:
            new_headers = args.header

        headers = parse_headers(new_headers)
    else:
        # Use the defaults from parse_headers
        headers = parse_headers("")

if __name__ == "__main__":
    # Set up the fuzzer for attack
    Fuzzer = Bypass_Fuzzer(url, proxies, args.smart_filter, hide,
        URL_PAYLOADS_FILE, HDR_PAYLOADS_TEMPLATE, IP_PAYLOADS_FILE)
    
    if not args.skip_headers:
        print("Attacking with header payloads...")
        Fuzzer.header_attack(req_method, headers, body_data, cookies)

    if not args.skip_urls:
        print("\nAttacking via URL & path...")
        Fuzzer.path_attack(req_method, headers, body_data, cookies)
    
    if not args.skip_td:   
        """
        Try sending with absolute domain (trailing dot).
        If proxy flag is set, skip this. Burp has issues processing 
        domains with the trailing dot and will freak out about illegal SSL.
        """
        if not args.proxy:
            print("\nTrailing dot attack...")
            Fuzzer.trailing_dot_attack(req_method, headers, body_data, cookies)
        else:
            print("\nProxy flag was detected. Skipping trailing dot attack...")
    
    if not args.skip_method:
        print("\nAttacking via different verbs...")
        Fuzzer.verb_attack(req_method, headers, body_data, cookies)

    # print("\nSending OPTIONS request. Inspect the response...")
    # send_options(url, headers, cookies, PROXIES)
