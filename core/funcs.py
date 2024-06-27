import json

from http.cookies import SimpleCookie


def is_json(some_json):
    """
    Check if a string is a valid JSON
    """
    try:
        json.loads(some_json)
        return True

    except ValueError:
        return False


def parse_headers(headers_to_parse):
    """
    Parse headers from the command line
    """
    if headers_to_parse:
        req_headers = {}
        headers = {
            x.split(":", 1)[0]: x.split(":", 1)[1].strip() for x in headers_to_parse
        }
        req_headers.update(headers)

        if "User-Agent" not in headers:
            req_headers.update(
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
                }
            )

    else:
        # Set default headers
        req_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
        }

    return req_headers


def parse_cookies(cookies_arg):
    """
    Parse cookies from the command line
    """
    cookie = SimpleCookie()
    cookie.load(cookies_arg)
    cookies = {key: value.value for key, value in cookie.items()}

    return cookies
