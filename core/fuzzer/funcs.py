import requests

from random import choice
from urllib.parse import urlsplit, urlunsplit


def setup_url_payloads(url, url_payloads_file):
    """Set up URL & path payloads"""

    # Load payloads file
    url_payloads = []
    with open(url_payloads_file, "r") as pf:
        payloads = pf.read().splitlines()

    # SplitResult(scheme='https', netloc='example.com', path='/test/test2',
    # params='', query='p1=1&p2=2', fragment='')
    parts = urlsplit(url)
    og_path_pieces = list(filter(None, parts.path.split("/")))  # clear the empty item

    new_paths = []
    # new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
    for i, piece in enumerate(og_path_pieces):
        for payload in payloads:
            new_path_pieces = list(og_path_pieces)  # get fresh copy of OG path
            new_path_pieces[i] = f"{payload}{piece}"  # xtest1/test2/test3
            new_paths.append("/".join(new_path_pieces))

            new_path_pieces = list(og_path_pieces)
            new_path_pieces[i] = f"{piece}{payload}"  # test1x/test2/test3
            new_paths.append("/".join(new_path_pieces))

            new_path_pieces = list(og_path_pieces)
            new_path_pieces[i] = f"{payload}{piece}{payload}"  # xtest1x/test2/test3
            new_paths.append("/".join(new_path_pieces))

        # random capitals payloads
        for x in range(5):
            new_path_pieces = list(og_path_pieces)
            new_path_pieces[i] = "".join(
                choice((str.upper, str.lower))(c) for c in piece
            )
            new_paths.append("/".join(new_path_pieces))

    # add some extra goodies to the last piece of path
    new_query_payloads = []
    query_payloads = [
        "?debug=true",
        "?admin=true",
        "?user=admin",
        "?detail=true",
        ".html",
        "?.html",
        "%3f.html",
        ".json",
        "?.json",
        "%3f.json",
        ".php",
        "?.php",
        "%3f.php",
        "?wsdl",
        "/application.wadl?detail=true",
    ]

    for suffix in query_payloads:
        for x in range(3):
            capped_payload = "".join(choice((str.upper, str.lower))(c) for c in suffix)
            new_query_payloads.append(capped_payload)

    # join and dedupe the 2 suffix lists
    query_payloads.extend(new_query_payloads)
    query_payloads = sorted(set(query_payloads))

    if len(og_path_pieces) > 0:
        original_piece = og_path_pieces[-1]
        for payload in query_payloads:
            new_path_pieces[-1] = f"{og_path_pieces[-1]}{payload}"
            new_paths.append("/".join(new_path_pieces))
            new_path_pieces[i] = original_piece

    # sort and dedupe
    new_paths = sorted(set(new_paths))

    original_query = parts.query
    original_parts = parts
    for p in new_paths:
        parts = original_parts
        # Keep an eye out for payloads that have an "extra" suffix
        if any(extra in p.split("/")[-1] for extra in query_payloads):
            # Remove the orignal query string, add as a payload
            parts = parts._replace(query="", path=p)
            url_payloads.append(urlunsplit(parts))

            # if there's already a '?' in the path,
            # we need to add the original query string as addtl. params

            if original_query:
                parts = original_parts
                if "?" in p.split("/")[-1] or "%3f" in p.split("/")[-1].lower():
                    parts = parts._replace(query="", path=f"{p}&{original_query}")
                    url_payloads.append(urlunsplit(parts))
        else:
            parts = parts._replace(path=p)
            url_payloads.append(urlunsplit(parts))

    return url_payloads


def setup_header_payloads(url, header_payloads_template, ip_payloads_file, oob_payload=None):
    """Set up header payloads"""

    # ParseResult(scheme='https', netloc='example.com', path='/test/test2',
    # params='', query='p1=1&p2=2', fragment='')
    parsed = urlsplit(url)
    path = parsed.path  # /test/test2

    header_payloads = []

    with open(header_payloads_template, "r") as pf:
        header_templates = pf.read().splitlines()

    with open(ip_payloads_file, "r") as pf:
        ip_payloads = pf.read().splitlines()

    for header in header_templates:
        if "{IP PAYLOAD}" in header:
            for ip_payload in ip_payloads:
                header_payloads.append(header.replace("{IP PAYLOAD}", ip_payload))
        elif "{WHITESPACE PAYLOAD}" in header:
            for ws_payload in [" "]:
                header_payloads.append(
                    header.replace("{WHITESPACE PAYLOAD}", ws_payload)
                )
        elif "{URL PAYLOAD}" in header:
            header_payloads.append(header.replace("{URL PAYLOAD}", url))
        elif "{PATH PAYLOAD}" in header:
            header_payloads.append(header.replace("{PATH PAYLOAD}", path))
        elif "{OOB PAYLOAD}" in header:
            if oob_payload:
                oob_parsed = urlsplit(oob_payload)
                if oob_parsed.scheme:
                    oob_payload = oob_parsed.netloc
                else:
                    oob_payload = oob_parsed.path
                header_payloads.append(header.replace("{OOB PAYLOAD}", f"http://{oob_payload}"))
                header_payloads.append(header.replace("{OOB PAYLOAD}", f"https://{oob_payload}"))
        elif "{OOB DOMAIN PAYLOAD}" in header:
            if oob_payload:
                oob_parsed = urlsplit(oob_payload)
                if oob_parsed.scheme:
                    oob_payload = oob_parsed.netloc
                else:
                    oob_payload = oob_parsed.path
                header_payloads.append(header.replace("{OOB DOMAIN PAYLOAD}", oob_payload))
        else:
            header_payloads.append(header)

    # TODO: prepend stuff to host header

    return header_payloads


def send_header_attack(s, url, method, headers, body_data, cookies, payload):
    hdr = payload.split(" ")[0].strip(":")

    # preserve existing header value
    preserve_header_value = None
    if hdr in headers:
        preserve_header_value = headers[hdr]

    headers[hdr] = payload.split(" ")[1]

    req = requests.Request(
        url=url, method=method, data=body_data, cookies=cookies, headers=headers
    )

    prep = s.prepare_request(req)
    prep.url = url

    success, retry = False, 1
    last_error = None
    while not success:
        if retry > 2:
            print("Tried 2 times.")
            print(f"Last error I got: \t{last_error}")
            return None

        try:
            # has fragmemnts in url at this point
            response = s.send(prep, verify=False, allow_redirects=False)
            success = True

        except Exception as e:
            last_error = e
            print(f"Header payload causing a hang-up: {payload}  Retrying...({retry})")

        retry += 1

    if preserve_header_value:  # reset to OG value
        headers[hdr] = preserve_header_value
    else:
        del headers[hdr]

    return response


def send_url_attack(s, payload, method, headers, body_data, cookies):
    req = requests.Request(
        url=payload, method=method, data=body_data, cookies=cookies, headers=headers
    )

    prep = s.prepare_request(req)
    prep.url = payload

    success, retry = False, 1
    last_error = None
    while not success:
        if retry > 2:
            print("Tried 2 times.")
            print(f"Last error I got: \t{last_error}")
            return None

        try:
            # has fragmemnts in url at this point
            response = s.send(prep, verify=False, allow_redirects=False)
            success = True

        except Exception as e:
            last_error = e
            print(f"Path payload causing a hang-up: {payload}  Retrying...({retry})")

        retry += 1

    return response


def send_method_attack(s, url, method, headers, body_data, cookies):
    success, retry = False, 1
    last_error = None
    while not success:
        if retry > 2:
            print("Tried 2 times.")
            print(f"Last error I got: \t{last_error}")
            return None
        try:
            response = s.request(
                method,
                url,
                data=body_data,
                cookies=cookies,
                headers=headers,
                verify=False,
                allow_redirects=False,
            )

            success = True

        except Exception as e:
            last_error = e
            print(f"Method causing a hang-up: {method}  Retrying...{retry}")

        retry += 1

    return response


def send_method_override_header(s, url, override_header, override_method, headers, body_data, cookies):
    hdr = override_header
    
    # preserve existing header value
    preserve_header_value = None
    if hdr in headers:
        preserve_header_value = headers[hdr]

    # set the payload
    headers[hdr] = override_method

    success, retry = False, 1
    last_error = None
    while not success:
        if retry > 2:
            print("Tried 2 times.")
            print(f"Last error I got: \t{last_error}")
            return None
        try:
            response = s.request(
                "POST",
                url,
                data=body_data,
                cookies=cookies,
                headers=headers,
                verify=False,
                allow_redirects=False,
            )

            success = True

        except Exception as e:
            last_error = e
            print(f"Method override causing a hang-up: {override_method}  Retrying...({retry})")

        retry += 1

    if preserve_header_value:  # reset to OG value
        headers[hdr] = preserve_header_value
    else:
        del headers[hdr]

    return response


def send_method_override_parameter(s, url, override_param, override_method, headers, body_data, cookies):
    payload = f"{override_param}={override_method}"

    parsed = urlsplit(url)

    if parsed.query:
        payload = f"&{payload}"
    else:
        payload = f"?{payload}"
    parsed = parsed._replace(query=f"{parsed.query}{payload}")
    
    url = urlunsplit(parsed)
    req = requests.Request(
        url=url, method="POST", data=body_data, cookies=cookies, headers=headers
    )

    prep = s.prepare_request(req)
    prep.url = url

    success, retry = False, 1
    last_error = None
    while not success:
        if retry > 2:
            print("Tried 2 times.")
            print(f"Last error I got: \t{last_error}")
            return None

        try:
            # has fragmemnts in url at this point
            response = s.send(prep, verify=False, allow_redirects=False)
            success = True

        except Exception as e:
            last_error = e
            print(f"Method override payload causing a hang-up: {payload}  Retrying...({retry})")

        retry += 1

    return response


def send_http_proto_attack(s, url, method, headers, body_data, cookies):
    req = requests.Request(method, url, data=body_data, cookies=cookies)
    prep = s.prepare_request(req)

    # Remove headers. These are 1 line protocols.
    prep.headers = {}

    success, retry = False, 1
    last_error = None
    while not success:
        if retry > 2:
            print("Retried 2 times.")
            print(f"Last error I get: \t{last_error}")
            return None
        try:
            response = s.request(
                method,
                url,
                data=body_data,
                cookies=cookies,
                headers={},
                verify=False,
                allow_redirects=False,
            )

            success = True

        except Exception as e:
            last_error = e
            print(f"Error while trying proto attack. Retrying...{retry}")

        retry += 1

    return response
