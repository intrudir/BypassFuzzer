from http.server import BaseHTTPRequestHandler
from io import BytesIO


class HTTPRequestReader(BaseHTTPRequestHandler):
    def __init__(self, raw_http_request):
        self.rfile = BytesIO(raw_http_request.encode('utf-8'))
        self.raw_requestline = self.rfile.readline()
        
        # BaseHTTPRequestHandler doesn't support HTTP/2 
        # so we gotta work around it
        http_2 = False
        if 'HTTP/2' in self.raw_requestline.decode():
            self.raw_requestline = self.raw_requestline.decode().replace("HTTP/2", "HTTP/1.1").encode()
            http_2 = True
            
        self.error_code = self.error_message = None
        self.parse_request()

        if http_2:
            self.request_version = "HTTP/2"

        self.headers = dict(self.headers)
        # Data
        try:
            self.data = raw_http_request[raw_http_request.index(
                '\n\n')+2:].rstrip()
        except ValueError:
            self.data = None

        # Cookies
        self.cookies = {}
        raw_cookies = self.headers.get('cookie')
        if raw_cookies:
            for raw_cookie in raw_cookies.split(';'):
                cookie_parts = raw_cookie.split('=')
                cookie_name = cookie_parts[0].strip()
                cookie_value = ''.join(cookie_parts[1:]).strip()
                self.cookies[cookie_name] = cookie_value

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message