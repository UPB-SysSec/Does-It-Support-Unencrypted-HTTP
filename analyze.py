import socket
import argparse

SUCCESS = "SUCCESS"
FAILURE = "FAILURE"
TIMEOUT = "TIMEOUT"
MAX_REDIRECT = "MAX REDIRECT"
REDIRECT = "REDIRECT"
HTTPS_REDIRECT = "HTTPS REDIRECT"

BUFFER_SIZE = 4096

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"

def main():
    # do command line stuff
    # max redirect follows, debug, and analyzed server
    # optional ip
    # TODO: fill with values

    parser = argparse.ArgumentParser(description='Analyzes servers for unencrypted HTTP support.',
                                     usage='%(prog)s [options]', add_help=True)

    parser.add_argument('hostname', type=str, help='The hostname of the server to analyze')
    parser.add_argument('--path', type=str, default="/", help='The path to request from the server')
    parser.add_argument('--ip', type=str, default=None, help='The IP of the server to analyze')
    parser.add_argument('--port', type=int, default=80, help='The port of the server to analyze')
    parser.add_argument('--debug', type=bool, default=False, action=argparse.BooleanOptionalAction,
                        help='Whether to print debug output')
    parser.add_argument('--redirect_depth', type=int, default=2, help='The maximum depth of redirects to follow')
    parser.add_argument('--timeout', type=int, default=5, help='The timeout for socket operations')
    args = parser.parse_args()
    Analyzer(args.hostname, args.path, args.ip, args.port, args.debug, args.redirect_depth, args.timeout).analyze()

class Analyzer:
    def __init__(self, hostname: str, path: str, ip: str = None, port: int =  80, debug: bool = False, redirect_depth: int = 1, timeout: int = 5):
        self.hostname = hostname
        self.path = path
        self.ip = ip
        self.port = port
        self.debug = debug
        self.redirect_depth = redirect_depth
        self.timeout = timeout

    def analyze(self):
        # resolve hostname if necessary
        if self.ip is None:
            self._debug("No IP provided, attempting to resolve hostname")
            try:
                self.ip = socket.gethostbyname(self.hostname)
                self._debug("Resolved hostname " + self.hostname + " to IP: " + self.ip)
            except Exception as e:
                self._debug("Failed to resolve hostname " + self.hostname + " with Exception: " + str(e))
                print("No IP provided and cannot resolve hostname for " + self.hostname + ". Provide reachable IP address or resolvable hostname.")
                exit(255)
        else:
            self._debug("Using given IP " + self.ip + " on " + self.hostname)

        # reachability check
        reachable = self.analyze_tcp_reachability()
        if reachable == TIMEOUT:
            print("Cannot open TCP connection to " + self.hostname + " due to timeout (" + str(self.timeout) + "s). Is the server online?")
        elif reachable == FAILURE:
            print("Cannot open TCP connection to " + self.hostname + " due to non-timeout error. Is the server online?")
        elif reachable == SUCCESS:
            print("Server online. Scanning!")

        try:
            ret_09 = self.analyze_http09()
        except Exception as e:
            self._debug("Error while analyzing HTTP/0.9: " + str(e))
            ret_09 = FAILURE
        try:
            ret_10 = self.analyze_http10(self.redirect_depth)
        except Exception as e:
            self._debug("Error while analyzing HTTP/1.0: " + str(e))
            ret_10 = FAILURE
        try:
            ret_11 = self.analyze_http11(self.redirect_depth)
        except Exception as e:
            self._debug("Error while analyzing HTTP/1.0: " + str(e))
            ret_11 = FAILURE
        # TODO: analyze_http2_prior_knowledge()
        # TODO: analyze_http2_upgrade()
        print("\n#####################\n")
        print("HTTP/0.9: " + ret_09)
        print("HTTP/1.0: " + ret_10)
        print("HTTP/1.1: " + ret_11)
        # analyze server for raw http support

    def analyze_http09(self) -> str:
        # open and connect socket
        sock = self.open_socket()
        if self.connect_socket(sock) != SUCCESS:
            return FAILURE
        # send 09 request to server
        try:
            sock.send(self.create_http_09_request())
        except Exception as e:
            self._debug("Could not send HTTP/0.9 request to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE
        # receive response
        response = self.receive_ascii_response(sock)
        if response == FAILURE:
            return FAILURE
        try:
            if response.lower().startswith("<html>"):
                # interpret any data as success for HTTP/0.9
                self._debug("HTTP/0.9 response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
                return SUCCESS
            else:
                # TODO: find better way to check for HTTP/0.9 response, maybe check for 1.0 response?
                self._debug("Could not interpret response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") as HTTP/0.9 response.")
                return FAILURE
        except Exception as e:
            self._debug("Could not interpret response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE


    def analyze_http10(self, recursion: int) -> str:
        return self.analyze_http1x("HTTP/1.0", recursion)

    def analyze_http11(self, recursion: int) -> str:
        return self.analyze_http1x("HTTP/1.1", recursion)

    def analyze_http1x(self, version: str, recursion: int):
        if recursion == -1:
            return "Max redirect"
        # open and connect socket
        sock = self.open_socket()
        if self.connect_socket(sock) != SUCCESS:
            return FAILURE
        # send 1x request to server
        try:
            sock.send(self.create_http1x_request(version))
        except Exception as e:
            self._debug("Could not send HTTP/1.x request to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE
        # receive response
        response = self.receive_ascii_response(sock)
        if response == FAILURE:
            return FAILURE
        try:
            status, headers, http_version = self.parse_http1_response(response)
        except Exception as e:
            self._debug("Failed to parse HTTP/1 response: " + response + " with exception: " + str(e))
            return FAILURE
        if status == 200:
            self._debug("HTTP/1.x response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
            return SUCCESS
        elif status == 301 or status == 302:
            # redirect
            redirect = self.update_redirect(headers)
            if redirect != SUCCESS:
                return redirect
            return REDIRECT + "(" + self.hostname + self.path + ") -> " + self.analyze_http1x(version, recursion - 1)
        else:
            self._debug("Cannot follow received redirect without Location header")
            return FAILURE

    def update_redirect(self, headers: dict) -> str:
        """
        Updates self.hostname and self.path with the new location from the headers.
        """
        if "location" not in headers:
            self._debug("No location header in redirect response.")
            return FAILURE

        # dont follow https redirects
        redirect_hostname = headers["location"]
        if redirect_hostname.startswith("https://"):
            self._debug("Redirect to HTTPS site" + redirect_hostname + ", not following")
            return HTTPS_REDIRECT
        # extract new hostname and path
        if "://" in redirect_hostname:
            # cut optional http://
            redirect_hostname = redirect_hostname.split("://")[1]
        if "/" in redirect_hostname:
            redirect_hostname, redirect_path = redirect_hostname.split("/", 1)
            redirect_path = "/" + redirect_path
        else:
            redirect_path = "/"
        # detect stagnant redirects
        if redirect_path == self.path and redirect_hostname == self.hostname:
            self._debug("Redirect to same hostname detected")
            return FAILURE
        else:
            # update path and hostname
            self._debug("Redirect to " + redirect_hostname + redirect_path)
            self.path = redirect_path
            self.hostname = redirect_hostname
        return SUCCESS

    def analyze_http2_prior_knowledge(self) -> str:
        pass
        # send http 2 request and check if 200 response
        # call recursively if redirect to other http site

    def analyze_http2_upgrade(self) -> str:
        pass
        # send http1 upgrade, check if 101 response, and if yes check if following http/2 is returned 200
        # call recursively if redirect to other http site

    def create_http_09_request(self) -> bytes:
        return b"GET " + self.path.encode("ASCII") + b"\r\n"

    def create_http1x_request(self, version: str) -> bytes:
        return (
                b"GET " + self.path.encode("ASCII") + b" " + version.encode("ASCII") + b"\r\n" +
                b"Host: " + self.hostname.encode("ASCII") + b"\r\n" +
                b"User-Agent: " + USER_AGENT.encode("ASCII") + b"\r\n"
                b"Connection: close\r\n" +
                b"\r\n"
        )

    def parse_http1_response(self, response: str):
        """
        Extracts the status code, headers, and HTTP version from an HTTP/1 response.

        :param response: The encoded HTTP response
        :return: The status code, headers, and HTTP version
        """
        response_lines = response.split('\r\n')
        status = int(response_lines[0].split(' ')[1])
        http_version = response_lines[0].split(' ')[0].split('/')[1]
        headers = {}
        for line in response_lines[1:]:
            if line == '':
                break

            key, value = line.split(':', 1)
            key = key.strip().lower()
            headers[key] = value.strip().lower()

        return status, headers, http_version

    def open_socket(self) -> socket.socket:
        self._debug("Opening TCP socket to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        return sock

    def connect_socket(self, sock: socket.socket) -> str:
        try:
            sock.connect((self.ip, self.port))
        except Exception as e:
            self._debug("Could not open TCP socket to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE
        self._debug("Successfully opened TCP socket to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
        return SUCCESS

    def receive_ascii_response(self, sock: socket.socket) -> str:
        try:
            response = sock.recv(BUFFER_SIZE)
        except Exception as e:
            self._debug("Could not receive response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE
        # extract status code, http version, and headers
        self._debug("Received response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + "): " + response.hex())
        try:
            response = response.decode("ASCII")
            self._debug("Decoded response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + "): " + response)
        except Exception as e:
            self._debug("Could not decode response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE
        return response

    def resolve_hostname(self) -> str:
        ip = socket.gethostbyname(self.hostname)
        self._debug("Resolved hostname " + self.hostname + " to IP: " + ip)
        return ip

    def analyze_tcp_reachability(self) -> str:
        # open tcp socket to ip
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.ip, self.port))
            self._debug("Successfully opened TCP socket to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
            return SUCCESS
        except socket.timeout as e:
            self._debug("Could not open TCP socket to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return TIMEOUT
        except Exception as e:
            self._debug("Could not open TCP socket to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE

    def _debug(self, string: str) -> None:
        if self.debug:
            print("DEBUG:" + string)

if __name__ == '__main__':
    main()