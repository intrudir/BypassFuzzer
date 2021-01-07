#!/usr/bin/env python3

from urllib.parse import urlparse, urlunparse
from http.cookies import SimpleCookie
import urllib, sys, os, argparse, requests

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

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1"}

scriptDir = os.path.dirname(__file__)
payloads_file = os.path.join(scriptDir, 'payloads.txt')

with open(payloads_file, 'r') as pf:
    payloads = pf.read().splitlines()

def setup_payloads(parsed, pathPieces, payloads):
    paths = []
    urls = []
    for i, piece in enumerate(pathPieces):
        last = pathPieces[len(pathPieces)-1]
        for payload in payloads:
            # prefix payload
            pathPieces[i] = "{}{}".format(payload, piece)
            paths.append('/'.join(pathPieces))
            pathPieces[i] = piece

            # suffix payload
            pathPieces[i] = "{}{}".format(piece, payload)
            paths.append('/'.join(pathPieces))
            pathPieces[i] = piece

    # sort and dedupe
    paths = sorted(set(paths))

    for p in paths:
        parsed = parsed._replace(path=p)
        urls.append(urlunparse(parsed))

    return urls


def send_header_payloads(url, headers, cookies, proxies, h, p):
    headers[h] = p
    resp = requests.get(url, cookies=cookies, proxies=proxies, headers=headers, verify=False)
    headers.pop(h)

    return resp.status_code, resp.text


def send_url_payloads(s, url, cookies, proxies):
    s = requests.Session()
    r = requests.Request("GET", url, cookies=cookies, headers=headers)
    #prep = r.prepare()
    prep = s.prepare_request(r)
    prep.url = url

    retry = 0
    while retry <= 3:
        try:
            resp = s.send(prep, verify=False)
        except requests.exceptions.ConnectionError as e:
            print(e)
            retry += 1
        else:
            break
    else:
        print("Retried 3 times. Exiting.")
        sys.exit(1)

    return resp.status_code, resp.text


def send_options(url, cookies, proxies):
    resp = requests.options(url, cookies=cookies, proxies=proxies, headers=headers, verify=False)
    print("Response code: {}   Response length: {}   Sent OPTIONS method. \n".format(resp.status_code, len(resp.text)))

    if len(resp.text) < 1:
        print("Response length was 0 so probably NOT worth checking out....\n")

    print("Response Headers: ")
    for h, v in resp.request.headers.items():
        print("{}: {}".format(h, v))


# if proxy, set it for requests
if args.proxy:
    try:
        proxies = {"http": args.proxy.split('//')[1],
                   "https": args.proxy.split('//')[1]
                   }
    except (IndexError, ValueError):
        print("invalid proxy specified")
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

# https://example.com/test/test2?p1=1&p2=2
url = args.url
# ParseResult(scheme='https', netloc='example.com', path='/test/test2',
# params='', query='p1=1&p2=2', fragment='')
parsed = urlparse(url)
path = parsed.path  # /test/test2
query = parsed.query  # p1=1p2=2
pathPieces = ' '.join(parsed.path.split('/')).split()  # ['test', 'test2']
url_payloads = setup_payloads(parsed, pathPieces, payloads)

header_payloads = {
    "X-Original-URL": path,
    "X-Forwarded-For": "127.0.0.1",
    "X-Custom-IP-Authorization": "127.0.0.1"
    }

for h, p in header_payloads.items():
    resp_code, resp_text = send_header_payloads(url, headers, cookies, proxies, h, p)
    MSG = "Response Code: {}\tLength: {}\tHeader: {}: {}".format(resp_code, len(resp_text), h, p)
    if str(resp_code) not in hide["codes"] and str(len(resp_text)) not in hide["lengths"]:
        print(MSG)

s = requests.Session()
s.proxies = proxies
for url in url_payloads:
    parsed = urlparse(url)
    path = parsed.path
    resp_code, resp_text = send_url_payloads(s, url, cookies, proxies)
    MSG = "Response Code: {}\tLength: {}\tPath: {}".format(resp_code, len(resp_text), path)
    if str(resp_code) not in hide["codes"] and str(len(resp_text)) not in hide["lengths"]:
        print(MSG)

send_options(url, cookies, proxies)
