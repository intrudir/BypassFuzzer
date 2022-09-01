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


    def show_results(self, response, payload, hide):
        msg = f"Response Code: {response.status_code}\tLength: {len(response.text)}\tPayload: {payload}"

        if response.status_code > 400:
            msg = self.colors["red"] + msg
        elif response.status_code >= 300 and response.status_code < 400:
            msg = self.colors["white"] + msg
        elif response.status_code < 300 and response.status_code >= 200:
            msg = self.colors["green"] + msg

        if self.Filter:
            if self.Filter.check(response.status_code, str(len(response.text))):
                print(msg)
        else:
            if str(response.status_code) not in hide["codes"] and str(len(response.text)) not in hide["lengths"]:
                print(msg)

        # Uncomment to see what the full URL looked like when sent
        # print(f'URL Sent: {response.url}')


    def header_attack(self, method, headers, body_data, cookies):
        if self.Filter:
            self.Filter._db = {}

        session = requests.Session()
        session.proxies = self.proxies

        for payload in self.header_payloads:
            response, payload = send_header_attack(session, self.url, method, headers, body_data, cookies, payload)
            self.show_results(response, payload, self.hide)


    def path_attack(self, method, headers, body_data, cookies):
        if self.Filter:
            self.Filter._db = {}

        session = requests.Session()
        session.proxies = self.proxies

        for payload in self.url_payloads:
            req, response = send_url_attack(session, payload, method, headers, body_data, cookies)
            resp_parsed = urlparse(response.url)
    
            if resp_parsed.fragment:
                resp_path = resp_parsed.path + '#' + resp_parsed.fragment
            else:
                resp_path = resp_parsed.path

            self.show_results(response, resp_path, self.hide)


    def trailing_dot_attack(self, method, headers, body_data, cookies):
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
                
                self.show_results(response, payload, self.hide)

            except requests.exceptions.RequestException as e:
                print(f"Path payload causing a hang-up: {payload}")
                print(f"Error I get: \n\t{e}")
                print("Retrying...")
            
            retry += 1
