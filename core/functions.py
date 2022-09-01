import json

from http.cookies import SimpleCookie


def is_json(some_json):
  try:
    json.loads(some_json)
    return True

  except ValueError as e:
    return False
  

def parse_headers(headers_to_parse):
    if headers_to_parse:
        req_headers = {}
        headers = {x.split(":", 1)[0]: x.split(":", 1)[1].strip() for x in headers_to_parse}
        req_headers.update(headers)

        if not "User-Agent" in headers:
            req_headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"})

    else:
        # Set default headers
        req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"}
    
    return req_headers


def parse_cookies(cookies_arg):
    cookie = SimpleCookie()
    cookie.load(cookies_arg)
    cookies = {key: value.value for key, value in cookie.items()}

    return cookies
