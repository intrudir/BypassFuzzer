import colorama

from .funcs import *
from core.fuzzer.filter import SmartFilter


class Bypass_Fuzzer():
    def __init__(self, url, proxies, filter, hide, url_payloads_file, hdr_payloads_template, ip_payloads_file):
        self.url = url
        self.proxies = proxies
        self.hide = hide
        self.header_payloads = setup_header_payloads(self.url, hdr_payloads_template, ip_payloads_file)
        self.url_payloads = setup_url_payloads(self.url, url_payloads_file)

        # Only allow repeats of 8 common responses
        self.Filter = SmartFilter(repeats=8) if filter else None

        colorama.init(autoreset=True)
        self.colors = {
            "red": colorama.Fore.RED,
            "green": colorama.Fore.GREEN,
            "blue": colorama.Fore.BLUE,
            "yellow": colorama.Fore.YELLOW,
            "bright": colorama.Style.BRIGHT,
            "reset": colorama.Style.RESET_ALL
        }


    def show_results(self, response, payload, hide, show_resp_headers=False):
        msg = f"Response Code: {response.status_code}\tLength: {len(response.text)}\tPayload: {payload}"

        if response.status_code > 400:  # errors
            msg = self.colors["red"] + msg
        elif response.status_code >= 300 and response.status_code < 400: # redirects
            msg = self.colors["yellow"] + msg 
            msg += f"  -->   {response.headers['Location']}"  # Show destination
        elif response.status_code >= 200 and response.status_code < 300:  # OK
            msg = self.colors["green"] + msg

        if self.Filter:
            if self.Filter.check(response.status_code, str(len(response.text))):
                print(msg)
                
                if show_resp_headers:
                    print("Response Headers: ")
                    for h, v in response.headers.items():
                        print(f"\t{h}: {v}")
        else:
            if str(response.status_code) not in hide["codes"] and str(len(response.text)) not in hide["lengths"]:
                print(msg)
                
                if show_resp_headers:
                    print("Response Headers: ")
                    for h, v in response.headers.items():
                        print(f"\t{h}: {v}")

        # Uncomment to see what the full URL looked like when sent
        # print(f'URL Sent: {response.url}')


    def header_attack(self, method, http_vers, headers, body_data, cookies):
        if http_vers == "HTTP/2":
            print("NOTE: HTTP/2 was detected in your original request, but I can only do HTTP/1.1 for now.")

        if self.Filter:
            self.Filter._db = {}

        session = requests.Session()
        session.proxies = self.proxies

        for payload in self.header_payloads:
            response = send_header_attack(session, self.url, method, headers, body_data, cookies, payload)
            self.show_results(response, payload, self.hide, show_resp_headers=False)


    def path_attack(self, method, http_vers, headers, body_data, cookies):
        if http_vers == "HTTP/2":
            print("NOTE: HTTP/2 was detected in your original request, but I can only do HTTP/1.1 for now.")

        if self.Filter:
            self.Filter._db = {}

        session = requests.Session()
        session.proxies = self.proxies

        for payload in self.url_payloads:
            response = send_url_attack(session, payload, method, headers, body_data, cookies)
            resp_parsed = urlparse(response.url)
    
            if resp_parsed.fragment:
                resp_path = resp_parsed.path + '#' + resp_parsed.fragment
            else:
                resp_path = urlunparse(resp_parsed._replace(scheme="", netloc=""))

            self.show_results(response, resp_path, self.hide, show_resp_headers=False)


    def trailing_dot_attack(self, method, http_vers, headers, body_data, cookies):
        if http_vers == "HTTP/2":
            print("NOTE: HTTP/2 was detected in your original request, but I can only do HTTP/1.1 for now.")
        
        if self.Filter:
            self.Filter._db = {}

        session = requests.Session()
        session.proxies = self.proxies

        parsed = urlparse(self.url)
        og_domain = parsed.netloc

        if ':' in parsed.netloc:
            absolute_domain = parsed.netloc.split(':')[0] + '.:' + parsed.netloc.split(':')[1]
        else:
            absolute_domain = parsed.netloc + '.'

        parsed = parsed._replace(netloc=absolute_domain)
        url = urlunparse(parsed)
        headers["Host"] = absolute_domain
        
        req = requests.Request(
            url=url, method=method, data=body_data, cookies=cookies, headers=headers)
        
        prep = session.prepare_request(req)
        prep.url = url

        print("Sending payload with absolute domain...")
        payload = prep.url
        success, retry = False, 0
        while not success:
            if retry > 3:
                print("Retried 3 times.")
                break

            try:
                response = session.send(prep, verify=False)
                success = True
                
                self.show_results(response, payload, self.hide, show_resp_headers=True)

            except requests.exceptions.RequestException as e:
                print(f"Path payload causing a hang-up: {payload}")
                print(f"Error I get: \n\t{e}")
                print("Retrying...")
            
            retry += 1


    def verb_attack(self, method, http_vers, headers, body_data, cookies):
        if http_vers == "HTTP/2":
            print("NOTE: HTTP/2 was detected in your original request, but I can only do HTTP/1.1 for now.")
        
        if self.Filter:
            self.Filter._db = {}

        session = requests.Session()
        session.proxies = self.proxies

        methods = [
            "OPTIONS", "GET", "POST", "PUT", "CONNECT",
            "PATCH", "DELETE", "TRACE", "LOCK", "HACK"
            ]

        for method in methods:
            response = send_method_attack(session, self.url, method, headers, body_data, cookies)

            self.show_results(response, method, self.hide, show_resp_headers=True)

            if len(response.text) < 1:
                print("Response length was 0 so probably NOT worth checking out....\n")
            
    
    def http_proto_attack(self, method, headers, body_data, cookies):
        from http.client import HTTPConnection
        
        if self.Filter:
            self.Filter._db = {}

        session = requests.Session()
        session.proxies = self.proxies
        session.headers.clear()

        for http_vers in ["HTTP/1.0", "HTTP/0.9"]:
            HTTPConnection._http_vsn_str = http_vers
            response = send_http_proto_attack(session, self.url, method, headers, body_data, cookies)
            
            self.show_results(response, http_vers, self.hide, show_resp_headers=True)
