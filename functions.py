import urllib, requests, sys
from urllib.parse import urlparse, urlunparse


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
        elif self._db[key] >= self._repeats:
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
    path_pieces = ' '.join(parsed.path.split('/')).split()  # ['test', 'test2']

    url_payloads = []
    # Set up URL payloads
    with open(url_payloads_file, 'r') as pf:
        payloads = pf.read().splitlines()

    paths = []
    for i, piece in enumerate(path_pieces):
        path_pieces[len(path_pieces)-1]
        for payload in payloads:
            # prefix payload
            path_pieces[i] = "{}{}".format(payload, piece)
            paths.append('/'.join(path_pieces))
            path_pieces[i] = piece

            # suffix payload
            path_pieces[i] = "{}{}".format(piece, payload)
            paths.append('/'.join(path_pieces))
            path_pieces[i] = piece

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


def send_header_payloads(url, headers, cookies, proxies, payload):
    hdr = payload.split(" ")[0].strip(":")
    headers[hdr] = payload.split(" ")[1]
    response = requests.get(
        url, cookies=cookies, proxies=proxies,
        headers=headers, verify=False)
    headers.pop(hdr)

    return response, payload


def send_url_payloads(s, url, method, headers, data, cookies):
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


def send_options(url, headers, cookies, proxies):
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


def do_results(FILTER, response, payload, colors, args, hide):

    msg = "Response Code: {}\tLength: {}\tPayload: {}".format(
            response.status_code, len(response.text), payload)
    
    if response.status_code > 400:
        msg = colors["red"] + msg
    elif response.status_code >= 300 and response.status_code < 400:
        msg = colors["white"] + msg
    elif response.status_code < 300 and response.status_code >= 200:
        msg = colors["green"] + msg

    if args.smart_filter:
        if FILTER.check(response.status_code, str(len(response.text))):
            print(msg)
    else:
        if str(response.status_code) not in hide["codes"] and str(len(response.text)) not in hide["lengths"]:
            print(msg)

