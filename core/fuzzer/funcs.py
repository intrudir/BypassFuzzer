import requests

from urllib.parse import urlparse, urlunparse


def setup_url_payloads(url, url_payloads_file):
    ''' Set up URL & path payloads '''

    # ParseResult(scheme='https', netloc='example.com', path='/test/test2',
    # params='', query='p1=1&p2=2', fragment='')
    parsed = urlparse(url) 
    path = parsed.path  # /test/test2
    path_pieces = ' '.join(parsed.path.split('/')).split()  # ['test', 'test2']

    ### Set up URL payloads
    url_payloads = []
    with open(url_payloads_file, 'r') as pf:
        payloads = pf.read().splitlines()

    paths = []
    for i, piece in enumerate(path_pieces):
        for payload in payloads:
            # prefix payload
            path_pieces[i] = f"{payload}{piece}"
            paths.append('/'.join(path_pieces))
            path_pieces[i] = piece

            # suffix payload
            path_pieces[i] = f"{piece}{payload}"
            paths.append('/'.join(path_pieces))
            path_pieces[i] = piece

    # add some extra goodies to the last piece of path
    extra_suffix_payloads = [
        ".html", "?.html", "%3f.html", 
        ".json", "?.json", "%3f.json", 
        ".php", "?.php", "%3f.php",
        "/application.wadl?detail=true", "?debug=true"
        ]

    if len(path_pieces) > 0:
        original_piece = path_pieces[-1]
        for payload in extra_suffix_payloads:
            path_pieces[-1] = f"{path_pieces[-1]}{payload}"
            paths.append('/'.join(path_pieces))
            path_pieces[i] = original_piece
    
    # sort and dedupe
    paths = sorted(set(paths))

    original_query = parsed.query
    for p in paths:
        # Keep an eye out for payloads that have an "extra" suffix
        if any(extra in p.split('/')[-1] for extra in extra_suffix_payloads):
            # Remove the orignal query string, add as a payload
            parsed = parsed._replace(query="", path=p)
            url_payloads.append(urlunparse(parsed))

            # if there's already a '?' in the path, 
            # we need to add the original query string as addtl. params
            if '?' in parsed.path:
                parsed = parsed._replace(path=f"{p}&{original_query}")
                url_payloads.append(urlunparse(parsed))

            # add the original query string & add as a payload
            parsed = parsed._replace(query=original_query, path=p)
            url_payloads.append(urlunparse(parsed))
        else:
            parsed = parsed._replace(path=p)
            url_payloads.append(urlunparse(parsed))
 

    return url_payloads


def setup_header_payloads(url, header_payloads_template, ip_payloads_file):
    ''' Set up header payloads '''

    # ParseResult(scheme='https', netloc='example.com', path='/test/test2',
    # params='', query='p1=1&p2=2', fragment='')
    parsed = urlparse(url) 
    path = parsed.path  # /test/test2
 
    header_payloads = []

    with open(header_payloads_template, 'r') as pf:
        header_templates = pf.read().splitlines()

    with open(ip_payloads_file, 'r') as pf:
        ip_payloads = pf.read().splitlines()

    for header in header_templates:
        if "{IP PAYLOAD}" in header:
            for ip_payload in ip_payloads:
                header_payloads.append(header.replace("{IP PAYLOAD}", ip_payload))
        elif "{URL PAYLOAD}" in header:
            header_payloads.append(header.replace("{URL PAYLOAD}", url))
        elif "{PATH PAYLOAD}" in header:
            header_payloads.append(header.replace("{PATH PAYLOAD}", path))
        else:
            continue

    return header_payloads


def send_header_attack(s, url, method, headers, body_data, cookies, payload):
    
    hdr = payload.split(" ")[0].strip(":")
    headers[hdr] = payload.split(" ")[1]

    req = requests.Request(
        url=url, method=method, data=body_data, cookies=cookies, 
        headers=headers)

    prep = s.prepare_request(req)
    prep.url = url

    success, retry = False, 0
    while not success:
        if retry > 3:
            print("Retried 3 times.")
            return None

        try:
            # has fragmemnts in url at this point
            response = s.send(prep, verify=False, allow_redirects=False)
            success = True
        
        except Exception as e:
            print(f"Header payload causing a hang-up: {hdr}")
            print(f"Error I get: \n\t{e}")
            print("Retrying...")
        
        retry += 1

    headers.pop(hdr)
    return response


def send_url_attack(s, payload, method, headers, body_data, cookies):
    
    req = requests.Request(
        url=payload, method=method, data=body_data, 
        cookies=cookies, headers=headers)

    prep = s.prepare_request(req)
    prep.url = payload
    
    success, retry = False, 0
    while not success:
        if retry > 3:
            print("Retried 3 times.")
            return None

        try:
            # has fragmemnts in url at this point
            response = s.send(prep, verify=False, allow_redirects=False)
            success = True

        except Exception as e:
            print(f"Path payload causing a hang-up: {payload}")
            print(f"Error I get: \n\t{e}")
            print("Retrying...")

        retry += 1

    return response


def send_method_attack(s, url, method, headers, body_data, cookies):
    success, retry = False, 0
    while not success:
        if retry > 3:
            print("Retried 3 times.")
            return None
        try:
            response = s.request(
                method, url, data=body_data, cookies=cookies, 
                headers=headers, verify=False, allow_redirects=False)
            
            success = True
        
        except Exception as e:
            print(f"Method causing a hang-up: {method}")
            print(f"Error I get: \n\t{e}")
            print("Retrying...")

        retry += 1

    return response
