import urllib, requests, sys
from urllib.parse import urlparse, urlunparse

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1"}

class SmartFilter():
    """ All credit for this filter goes to whoever did this:
    https://gist.github.com/defparam/8067cc4eb0140399f2bcd5f66a860db4
    """
    def __init__(self, repeats=10):
        # our data base to keep track of history
        self._db = {}
        # the number of repeats allowed before muting future responses
        self._repeats = repeats

    def check(self, status, wordlen):
        # We make a directory key by concating status code + number of words
        key = str(status)+str(wordlen)
        # if never seen this key before, add it to the dictionary with 1 hit
        if key not in self._db:
            self._db[key] = 1
        # if key exists and it reached the repeat maximum, mute the response
        elif (self._db[key] >= self._repeats):
            return False
        # If the key hasn't reached the repeat limit,
        # add to the hit count and allow the response to be shown
        else:
            self._db[key] += 1

        return True


def setup_payloads(url, url_payloads_file, header_payloads_file):
    # ParseResult(scheme='https', netloc='example.com', path='/test/test2',
    # params='', query='p1=1&p2=2', fragment='')
    parsed = urlparse(url)
    path = parsed.path  # /test/test2
    query = parsed.query  # p1=1p2=2
    pathPieces = ' '.join(parsed.path.split('/')).split()  # ['test', 'test2']

    # Set up URL payloads
    with open(url_payloads_file, 'r') as pf:
        payloads = pf.read().splitlines()

    paths = []
    url_payloads = []
    for i, piece in enumerate(pathPieces):
        pathPieces[len(pathPieces)-1]
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
        url_payloads.append(urlunparse(parsed))

    # Set up header payloads
    with open(header_payloads_file, 'r') as pf:
        payloads = pf.read().splitlines()

    header_payloads = []
    path_header_payloads = {
        "X-Original-URL": path,
        "X-Rewrite-Url": path,
        "Referrer": url,
        "Refferer": url,
        "Referer": url
        }

    for h, p in path_header_payloads.items():
        header_payloads.append("{}: {}".format(h, p))

    for payload in payloads:
        header_payloads.append(payload)

    return url_payloads, header_payloads


def send_header_payloads(url, cookies, proxies, payload):
    hdr = payload.split(" ")[0].strip(":")
    headers[hdr] = payload.split(" ")[1]
    resp = requests.get(
        url, cookies=cookies, proxies=proxies,
        headers=headers, verify=False)
    headers.pop(hdr)

    return resp.status_code, resp.text, payload


def send_url_payloads(s, url, method, data, cookies):
    req = requests.Request(
        url=url, method=method, data=data, cookies=cookies, headers=headers)
    prep = s.prepare_request(req)
    prep.url = url

    retry = 0
    while retry <= 3:
        try:
            # has fragmemnts in url at this point
            response = s.send(prep, verify=False)
        except requests.exceptions.ConnectionError as e:
            print(e)
            retry += 1
        else:
            break
    else:
        print("Retried 3 times. Exiting.")
        sys.exit(1)

    # Uncomment to see what the full URL looked like when sent
    # print('Sent: {}'.format(resp.url))
    return req, response


def send_options(url, cookies, proxies):
    resp = requests.options(
        url, cookies=cookies, proxies=proxies, headers=headers, verify=False)
    print("Response code: {}   Response length: {}   \
        Sent OPTIONS method. \n".format(resp.status_code, len(resp.text)))

    if len(resp.text) < 1:
        print("Response length was 0 so probably NOT worth checking out....\n")

    print("Response Headers: ")
    for h, v in resp.request.headers.items():
        print("{}: {}".format(h, v))


def pretty_print_request(req):
    stuff = (
"""
-----------START-----------
Method: {}
Url: {}

Headers:
""").format(req.method, req.url)
    for k, v in req.headers.items():
        stuff += "{}: {}\n".format(k, v)
    stuff += '\n'

    if req.data:
        stuff += "body data: " + str(req.data)
    if req.json:
        stuff += "json: " + str(req.json)
    if req.params:
        stuff += "params: " + str(req.params)

    stuff += "\n-----------END-----------\n\n"

    return stuff
