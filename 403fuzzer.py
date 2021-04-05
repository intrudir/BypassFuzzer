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
    '-m', '--method', action="store", default='GET', dest='method',
    choices=('GET', 'POST', 'PUT', 'PATCH'),
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
    '-p', '--proxy', action="store", default=None, dest='proxy',
    help="Specify a proxy to use for requests \
        (e.g., http://127.0.0.1:8080)")
parser.add_argument(
    '-hc', action="store", default=None, dest='hc',
    help="Hide response code from output, single or comma separated")
parser.add_argument(
    '-hl', action="store", default=None, dest='hl',
    help="Hide response length from output, single or comma separated")
parser.add_argument(
    '-sf', '--smart', action="store_true", default=False, dest='smart_filter',
    help="Enable the smart filter")
parser.add_argument(
    '--save', action="store", default=None, dest='save',
    help="Saves stuff to a file when you get your specified response code")
parser.add_argument(
    '-sh', '--skip-headers', action="store_true", default=False, dest='skip_headers',
    help="Skip testing bypass headers")
parser.add_argument(
    '-su', '--skip-urls', action="store_true", default=False, dest='skip_urls',
    help="Skip testing path payloads")
args = parser.parse_args()


if len(sys.argv) <= 1:
    parser.print_help()
    print()
    sys.exit()

if args.smart_filter and (args.hc or args.hl):
    print("Can't do smart filter together with hide code or hide length yet")
    sys.exit(1)

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

# if headers are specified, parse them
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
    }

if args.header:
    add_headers = {x.split(":")[0]: x.split(":")[1].strip() for x in args.header}
    headers.update(add_headers)

# parse body data
# param1=value1&param2=value2 : {"param1": "test", "param2": "test"}
if args.data_params:
    data = dict(x.split("=") for x in args.data_params.split("&"))
else:
    data = {}

# Init smart SmartFilter
if args.smart_filter:
    FILTER = SmartFilter(repeats=8)  # Only allow repeats of 3 common responses

scriptDir = os.path.dirname(__file__)
url_payloads_file = os.path.join(scriptDir, 'url_payloads.txt')
hdr_payloads_file = os.path.join(scriptDir, 'header_payloads.txt')

# https://example.com/test/test2?p1=1&p2=2
url = args.url
url_payloads, header_payloads = setup_payloads(url, url_payloads_file, hdr_payloads_file)

s = requests.Session()
s.proxies = proxies

if not args.skip_headers:
    print("Sending header payloads...")
    for payload in header_payloads:
        response, payload = send_header_payloads(url, headers, cookies, proxies, payload)
        MSG = "Response Code: {}\tLength: {}\tHeader: {}".format(response.status_code, len(response.text), payload) 
        if args.smart_filter:
            if FILTER.check(response.status_code, str(len(response.text))):
                print(MSG)
        else:
            if str(response.status_code) not in hide["codes"] and str(len(response.text)) not in hide["lengths"]:
                print(MSG)

if not args.skip_urls:
    # First, try sending with absolute domain (trailing dot)
    # If proxy flag is set, skip this payload
    # Burp has issues processing domains with the trailing dot this and will 
    # freak out about illegal SSL 
    if not args.proxy:
        parsed = urlparse(url)
        og_domain = parsed.netloc               
        absolute_domain = parsed.netloc + '.' 
        parsed = parsed._replace(netloc=absolute_domain)
        url = urlunparse(parsed)
        headers["Host"] = absolute_domain
        req = requests.Request(
            url=url, method=args.method, data=data, cookies=cookies, headers=headers)
        prep = s.prepare_request(req)
        prep.url = url
        
        print("\nSending payload with absolute domain...")
        response = s.send(prep, verify=False)
        MSG = "Response Code: {}\tLength: {}\tPayload: {}\n".format(response.status_code, len(response.text), response.url) 
        if args.smart_filter:
            if FILTER.check(response.status_code, str(len(response.text))):
                print(MSG)
        else:
            if str(response.status_code) not in hide["codes"] and str(len(response.text)) not in hide["lengths"]:
                print(MSG)
        # Reset host header
        headers.pop("Host")
    else:
        print("\nProxy flag was detected. Skipping trailing dot payload...")

    # Start sending URL payloads
    print("\nSending URL payloads...")
    for url in url_payloads:
        req, response = send_url_payloads(s, url, args.method, headers, data, cookies)
        resp_parsed = urlparse(response.url)
        if resp_parsed.fragment:
            resp_path = resp_parsed.path + '#' + resp_parsed.fragment
        else:
            resp_path = resp_parsed.path
        MSG = "Response Code: {}\tLength: {}\tPath: {}".format(response.status_code, len(response.text), resp_path)
        if args.smart_filter:
            if FILTER.check(response.status_code, str(len(response.text))):
                print(MSG)
        else:
            if str(response.status_code) not in hide["codes"] and str(len(response.text)) not in hide["lengths"]:
                print(MSG)

        # save request info to saved.txt if matches specified code
        if str(response.status_code) == args.save:
            stuff = pretty_print_request(req)
            with open("saved.txt", 'a+') as of:
                of.write(stuff)

send_options(url, headers, cookies, proxies)
