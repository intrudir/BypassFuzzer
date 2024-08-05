from urllib.parse import urlsplit, urlunsplit
import http.client
import os
import colorama
import requests
from core.fuzzer.filter import SmartFilter
from core.fuzzer import funcs
from core.fuzzer.db_handler import DatabaseHandler

http.client._MAXHEADERS = 200


class BypassFuzzer:
    """
    Main class for the fuzzer
    """

    def __init__(self, url, proxies, sfilter, hide, url_payloads_file,
        hdr_payloads_template, ip_payloads_file, db_dir, oob_payload, save_interactions,
        db_name=None):
        """
        Initialize the fuzzer
        """
        self.payload_index = 1
        self.url = url
        self.proxies = proxies
        self.hide = hide
        self.header_payloads = funcs.setup_header_payloads(
            self.url, hdr_payloads_template, ip_payloads_file, oob_payload
        )
        self.oob_payload = oob_payload
        self.url_payloads = funcs.setup_url_payloads(self.url, url_payloads_file)

        # Only allow repeats of 8 common responses
        self.filter = SmartFilter(repeats=8) if sfilter else None

        colorama.init(autoreset=True)
        self.colors = {
            "red": colorama.Fore.RED,
            "green": colorama.Fore.GREEN,
            "blue": colorama.Fore.BLUE,
            "yellow": colorama.Fore.YELLOW,
            "bright": colorama.Style.BRIGHT,
            "reset": colorama.Style.RESET_ALL,
        }

        self.db_dir = db_dir
        self.db_handler = DatabaseHandler(self.db_dir, db_name)
        self.save_interactions = save_interactions

    @staticmethod
    def display_interaction(identifier, by='index', db_dir=None, db_name=None):
        if db_name is None:
            db_name = DatabaseHandler.get_latest_db(db_dir)

        # Check if the database exists
        db_path = os.path.join(db_dir, db_name)
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"Database {db_name} not found")

        db_handler = DatabaseHandler(db_dir, db_name)
        interactions = db_handler.load_interactions()
        interaction = None
        
        if by == 'index':
            if identifier < 0:
                print("Invalid interaction index")
                return
            for inter in interactions:
                if inter[0] == identifier:
                    interaction = inter
                    break
        elif by == 'payload':
            for inter in interactions:
                if inter[2] == identifier:
                    interaction = inter
                    break
            if not interaction:
                print(f"No interaction found for the given {by}")
                return

        if interaction:
            url_parts = urlsplit(interaction[3])
            if url_parts.query:
                path = url_parts.path + "?" + url_parts.query
            elif url_parts.fragment:
                path = url_parts.path + "#" + url_parts.fragment
            else:
                path = url_parts.path

            # Format request and response similar to Burp Suite's repeater window
            request_display = f"{interaction[4]} {path} HTTP/1.1\n"
            request_headers = eval(interaction[5])  # Convert string back to dictionary
            for key, value in request_headers.items():
                request_display += f"{key}: {value}\n"
            if interaction[6]:  # Check if there is a request body
                request_display += f"\n{interaction[6]}\n"

            response_display = f"HTTP/1.1 {interaction[7]}\n"
            response_headers = eval(interaction[8])  # Convert string back to dictionary
            for key, value in response_headers.items():
                response_display += f"{key}: {value}\n"
            response_display += f"\n{interaction[9]}\n"

            # Print formatted request, response, and payload
            print(f"Payload:\n{interaction[2]}\n")
            print(f"Request:\n{request_display}")
            print(f"Response:\n{response_display}")

    def show_results(self, response, payload, hide, show_resp_headers=False):
        """
        Show the results of the attack
        """

        msg = f"I: {self.payload_index}\t Response Code: {response.status_code}\tLength: {len(response.text)}\tPayload: {payload}"

        if response.status_code > 400:  # errors
            msg = self.colors["red"] + msg
        elif response.status_code >= 300 and response.status_code < 400:  # redirects
            msg = self.colors["yellow"] + msg
            msg += f"  -->   {response.headers['Location']}"  # Show destination
        elif response.status_code >= 200 and response.status_code < 300:  # OK
            msg = self.colors["green"] + msg

        if self.filter:
            if self.filter.check(response.status_code, str(len(response.text))):
                print(msg)

                if show_resp_headers:
                    print("Response Headers: ")
                    for h, v in response.headers.items():
                        print(f"\t{h}: {v}")
        else:
            if (
                str(response.status_code) not in hide["codes"]
                and str(len(response.text)) not in hide["lengths"]
            ):
                print(msg)

                if show_resp_headers:
                    print("Response Headers: ")
                    for h, v in response.headers.items():
                        print(f"\t{h}: {v}")

    def header_attack(self, method, http_vers, headers, body_data, cookies):
        """
        Attack with payloads in the headers
        """
        print("Attacking with header payloads...")

        if http_vers == "HTTP/2":
            print(
                "NOTE: HTTP/2 was detected in your original request, but I can only do HTTP/1.1 for now."
            )

        if self.filter:
            self.filter.db = {}

        session = requests.Session()
        session.proxies = self.proxies

        # preserve the original headers incase of an error
        og_headers = headers.copy()

        for payload in self.header_payloads:
            response = funcs.send_header_attack(
                session, self.url, method, headers, body_data, cookies, payload
            )

            if response is not None:
                self.show_results(response, payload, self.hide, show_resp_headers=False)
                if response.status_code in self.save_interactions:
                   self.db_handler.save_interaction(self.payload_index, response.request, response, payload)
            else:
                headers = og_headers.copy()  # reset headers when there's an error

            self.payload_index += 1        

    def trail_slash(self, method, http_vers, headers, body_data, cookies):
        """If the URL is: https://example.com/test/test2
        If the endpoint does not end in a slash, add a slash so it becomes https://example.com/test/test2/
        If the endpoint already ends in a slash, remove it so it becomes https://example.com/test/test2
        Compare response length and response code to original request
        """
        print("\nTrailing slash technique...")

        if http_vers == "HTTP/2":
            print(
                "NOTE: HTTP/2 was detected in your original request, but I can only do HTTP/1.1 for now."
            )

        if self.filter:
            self.filter.db = {}

        session = requests.Session()
        session.proxies = self.proxies
        parsed = urlsplit(self.url)

        if parsed.path[-1] == "/":
            print("\nRemoving trailing slash...")
            new_path = parsed.path[:-1]
        else:
            print("\nSingle trailing slash...")
            new_path = parsed.path + "/"

        parsed = parsed._replace(path=new_path)
        payload = urlunsplit(parsed)
        response = funcs.send_url_attack(
            session, payload, method, headers, body_data, cookies
        )

        if response is not None:
            self.show_results(response, payload, self.hide, show_resp_headers=False)
            if response.status_code in self.save_interactions:
                self.db_handler.save_interaction(self.payload_index, response.request, response, payload)
            
        self.payload_index += 1

    def path_attack(self, method, http_vers, headers, body_data, cookies):
        """
        Attack with payloads in the path
        """
        print("\n\nAttacking via URL & path...")

        if http_vers == "HTTP/2":
            print(
                "NOTE: HTTP/2 was detected in your original request, but I can only do HTTP/1.1 for now."
            )

        if self.filter:
            self.filter.db = {}

        session = requests.Session()
        session.proxies = self.proxies

        for payload in self.url_payloads:
            response = funcs.send_url_attack(
                session, payload, method, headers, body_data, cookies
            )

            if response is not None:
                # Payload should show path + any params
                if payload in self.url_payloads:
                    urlsplit_payload = urlsplit(payload)
                    if urlsplit_payload.query:
                        payload = urlsplit_payload.path + "?" + urlsplit_payload.query
                    elif urlsplit_payload.fragment:
                        payload = urlsplit_payload.path + "#" + urlsplit_payload.fragment
                    else:
                        payload = urlsplit_payload.path
                self.show_results(
                    response, payload, self.hide, show_resp_headers=False)
                if response.status_code in self.save_interactions:
                    self.db_handler.save_interaction(self.payload_index, response.request, response, payload)

            self.payload_index += 1

    def trailing_dot_attack(self, method, http_vers, headers, body_data, cookies):
        """
        Attack with absolute domain
        """
        print("\n\nTrailing dot attack...")
        if http_vers == "HTTP/2":
            print(
                "NOTE: HTTP/2 was detected in your original request, but I can only do HTTP/1.1 for now."
            )

        if self.filter:
            self.filter.db = {}

        session = requests.Session()
        session.proxies = self.proxies

        parsed = urlsplit(self.url)

        if ":" in parsed.netloc:
            absolute_domain = (
                parsed.netloc.split(":")[0] + ".:" + parsed.netloc.split(":")[1]
            )
        else:
            absolute_domain = parsed.netloc + "."

        parsed = parsed._replace(netloc=absolute_domain)
        url = urlunsplit(parsed)
        headers["Host"] = absolute_domain

        req = requests.Request(
            url=url, method=method, data=body_data, cookies=cookies, headers=headers
        )

        prep = session.prepare_request(req)
        prep.url = url

        print("Sending payload with absolute domain...")
        payload = prep.url
        success, retry = False, 0
        while not success:
            if retry > 2:
                print("Retried 3 times.")
                break

            try:
                response = session.send(prep, verify=False)

                if response is not None:
                    success = True
                    self.show_results(
                        response, payload, self.hide, show_resp_headers=True)
                    if response.status_code in self.save_interactions:
                        self.db_handler.save_interaction(self.payload_index, response.request, response, payload)

                self.payload_index += 1

            except requests.exceptions.RequestException as e:
                print(f"Path payload causing a hang-up: {payload}")
                print(f"Error I get: \n\t{e}")
                print("Retrying...")

            retry += 1


    def verb_attack(self, method, http_vers, headers, body_data, cookies):
        """
        Attack with different HTTP verbs
        """
        print("\n\nAttacking via different verbs...")

        if http_vers == "HTTP/2":
            print(
                "NOTE: HTTP/2 was detected in your original request, but I can only do HTTP/1.1 for now."
            )

        if self.filter:
            self.filter.db = {}

        session = requests.Session()
        session.proxies = self.proxies

        methods = [
            "OPTIONS",
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "TRACE",
            "LOCK",
            "CONNECT",
            "PROPFIND",
            "HACK",
        ]

        for method in methods:
            response = funcs.send_method_attack(
                session, self.url, method, headers, body_data, cookies
            )

            if response is not None:
                self.show_results(response, method, self.hide, show_resp_headers=True)
                if response.status_code in self.save_interactions:
                    self.db_handler.save_interaction(self.payload_index, response.request, response, method)

                if len(response.text) < 1:
                    print("Response length was 0 so probably NOT worth checking out....\n")

            self.payload_index += 1
        
        override_methods = [
            "GET",
            "PUT"
        ]
        override_method_headers = [
            "X-HTTP-Method-Override",
            "X-Method-Override"
            "X-HTTP-Method",
        ]
        override_method_parameters = [
            "x-http-method-override",
            "x-method-override",
            "method",
            "_method",
            "m",
            "_m",
        ]

        print("\n\nAttacking via METHOD OVERRIDE header...")
        # preserve the original headers incase of an error
        og_headers = headers.copy()
        for omh in override_method_headers:
            for om in override_methods:
                response = funcs.send_method_override_header(
                    session, self.url, omh, om, headers, body_data, cookies
                )

                if response is not None:
                    self.show_results(response, om, self.hide, show_resp_headers=True)
                else:
                    headers = og_headers.copy()  # reset headers when there's an error
        
        print("\n\nAttacking via METHOD OVERRIDE parameter...")
        for mop in override_method_parameters:
            for om in override_methods:
                om = om.lower()
                response = funcs.send_method_override_parameter(
                    session, self.url, mop, om, headers, body_data, cookies
                )

                if response is not None:
                    payload = f"{mop}={om}"
                    self.show_results(response, payload, self.hide, show_resp_headers=True)
                    if response.status_code in self.save_interactions:
                        self.db_handler.save_interaction(self.payload_index, response.request, response, payload)
                
                self.payload_index += 1


    def http_proto_attack(self, method, headers, body_data, cookies):
        """
        Attack with different HTTP versions
        """
        print("\n\nAttacking via different HTTP versions...")

        from http.client import HTTPConnection

        if self.filter:
            self.filter.db = {}

        session = requests.Session()
        session.proxies = self.proxies
        session.headers.clear()

        for http_vers in ["HTTP/1.0", "HTTP/0.9"]:
            HTTPConnection._http_vsn_str = http_vers
            response = funcs.send_http_proto_attack(
                session, self.url, method, headers, body_data, cookies
            )

            if response is not None:
                self.show_results(
                    response, http_vers, self.hide, show_resp_headers=True)
                if response.status_code in self.save_interactions:
                    self.db_handler.save_interaction(self.payload_index, response.request, response, http_vers)

            self.payload_index += 1
