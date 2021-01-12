#!/usr/bin/env python3

from http.cookies import SimpleCookie
import sys, os, argparse, requests
from functions import *


requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(
    description="use this script to fuzz endpoints that return a 401/403"
)
parser.add_argument(
    '-u', '--url', action="store", default=None, dest='url',
    help="Specify the target URL")
parser.add_argument(
     '-c', '--cookies', action="store", default=None, dest='cookies',
    help="Specify cookies to use in requests. \
         (e.g., --cookies \"cookie1=blah; cookie2=blah\")")
parser.add_argument(
    '-p', '--proxy', action="store", default=None, dest='proxy',
    help="Specify a proxy to use for requests \
            (e.g., http://localhost:8080)")
parser.add_argument(
    '-hc', action="store", default=None, dest='hc',
    help="Hide response code from output, single or comma separated")
parser.add_argument(
    '-hl', action="store", default=None, dest='hl',
    help="Hide response length from output, single or comma separated")
args = parser.parse_args()

if len(sys.argv) <= 1:
    parser.print_help()
    print()
    sys.exit()

# if proxy, set it for requests
if args.proxy:
    try:
        proxies = {"http": "http://" + args.proxy.split('//')[1],
                   "https": "http://" + args.proxy.split('//')[1]
                   }
    except (IndexError, ValueError):
        print("Invalid proxy specified. \n\
Needs to be something like http://127.0.0.1:8080")
        sys.exit(1)

else:
    proxies = None

# If cookies, parse them
if args.cookies:
    cookie = SimpleCookie()
    cookie.load(args.cookies)
    cookies = {key: value.value for key, value in cookie.items()}
else:
    cookies = {}

hide = {"codes": [], "lengths": []}
if args.hc:
    for i in args.hc.split(','):
        hide["codes"].append(i)
if args.hl:
    for i in args.hl.split(','):
        hide["lengths"].append(i)

scriptDir = os.path.dirname(__file__)
url_payloads_file = os.path.join(scriptDir, 'url_payloads.txt')
hdr_payloads_file = os.path.join(scriptDir, 'header_payloads.txt')

# https://example.com/test/test2?p1=1&p2=2
url = args.url
url_payloads, header_payloads = setup_payloads(url, url_payloads_file, hdr_payloads_file)

s = requests.Session()
s.proxies = proxies

for payload in header_payloads:
    resp_code, resp_text, payload = send_header_payloads(url, cookies, proxies, payload)
    MSG = "Response Code: {}\tLength: {}\tHeader: {}".format(resp_code, len(resp_text), payload)
    if str(resp_code) not in hide["codes"] and str(len(resp_text)) not in hide["lengths"]:
        print(MSG)

for url in url_payloads:
    parsed = urlparse(url)
    path = parsed.path
    resp_code, resp_text = send_url_payloads(s, url, cookies)
    MSG = "Response Code: {}\tLength: {}\tPath: {}".format(resp_code, len(resp_text), path)
    if str(resp_code) not in hide["codes"] and str(len(resp_text)) not in hide["lengths"]:
        print(MSG)

send_options(url, cookies, proxies)
