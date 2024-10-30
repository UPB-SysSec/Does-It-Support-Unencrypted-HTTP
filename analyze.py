import argparse
import socket
import traceback
from typing import Tuple, Union

import h2.connection

SUCCESS = "SUCCESS"
FAILURE = "FAILURE"
TIMEOUT = "TIMEOUT"
MAX_REDIRECT = "MAX REDIRECT"
REDIRECT = "REDIRECT"
HTTPS_REDIRECT = "HTTPS REDIRECT"

BUFFER_SIZE = 4096

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"

def main():
    """
    Main method. Initializes parser and starts Analyzer.
    """

    # prepare argument parser
    parser = argparse.ArgumentParser(description='Analyzes servers for unencrypted HTTP support.',
                                     usage='%(prog)s [options]', add_help=True,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('hostname', type=str, help='The hostname of the server to analyze')
    parser.add_argument('--path', type=str, default="/", help='The path to request from the server')
    parser.add_argument('--ip', type=str, default=None, help='The IP of the server to analyze. If not provided, the hostname is resolved. If present, prevents domain resolution after redirects.')
    parser.add_argument('--port', type=int, default=80, help='The port of the server to analyze')
    parser.add_argument('--http09', type=bool, default=False, action=argparse.BooleanOptionalAction, help="By default, HTT/0.9 is not analyzed. Provide --http09 to analyze the server for HTT/0.9 support. Return Type of HTT/0.9 probe is inconclusive, so run with debug or external analysis tool like Wireshark to verify the actual server answer.")
    parser.add_argument('--debug', type=bool, default=False, action=argparse.BooleanOptionalAction,
                        help='Whether to print debug output')
    parser.add_argument('--redirect_depth', type=int, default=2, help='The maximum depth of redirects to follow')
    parser.add_argument('--timeout', type=int, default=5, help='The timeout for socket operations')
    args = parser.parse_args()

    # start analyzing
    Analyzer(args.hostname, args.path, args.ip, args.port, args.http09, args.debug, args.redirect_depth, args.timeout).analyze()

class Analyzer:
    """
    Analyzes a website for unencrypted HTTP support.
    """

    def __init__(self, hostname: str, path: str, ip: str = None, port: int =  80, http09:bool=False, debug: bool = False, redirect_depth: int = 1, timeout: int = 5):
        """
        Initializes Analyzer.
        :param hostname: The hostname of the server to analyze. Used in the Host header of HTTP requests. (required)
        :param path: The path to request from the server. (required)
        :param ip: The IP of the server to analyze. If not provided, the hostname is resolved. (optional)
        :param port: The port of the server to analyze. (default: 80)
        :param http09: Whether to analyze HTTP/0.9 support. (default: False)
        :param debug: Enables debug statements if True. (default: False)
        :param redirect_depth: The maximum depth of HTTP redirects to follow. (default: 1)
        :param timeout: The timeout for socket operations in seconds. (default: 5)
        """
        self.hostname = hostname
        self.path = path
        self.ip = ip
        self.port = port
        self.http09 = http09
        self.debug = debug
        self.redirect_depth = redirect_depth
        self.timeout = timeout

        self._resolve_hostname = self.ip is None

    def analyze(self):
        """
        Analyzes the server for unencrypted HTTP support.

        The following steps are performed:
        1. Resolve hostname if necessary
        2. Check TCP connectivity of server
        3. Analyze HTTP/0.9 support if requested
        4. Analyze HTTP/1.0 support
        5. Analyze HTTP/1.1 support
        6. Analyze HTTP/2.0 support with prior knowledge
        7. Analyze HTTP/2.0 support with upgrade mechanism
        8. Print results
        """
        print(self.hostname + " analysis started.")
        # resolve hostname if necessary
        if self._resolve_hostname:
            self._debug("No IP provided, attempting to resolve hostname")
            if self.resolve_hostname() == FAILURE:
                print(
                    "No IP provided and cannot resolve hostname for " + self.hostname + ". Provide reachable IP address or resolvable hostname.")
                exit(255)
        else:
            print("Using given IP " + self.ip + " on " + self.hostname)

        # reachability check
        reachable = self.analyze_tcp_reachability()
        if reachable == TIMEOUT:
            print("Cannot open TCP connection to " + self.hostname + ":" + str(self.port) + " due to timeout (" + str(self.timeout) + "s). Is the server online?")
            return TIMEOUT
        elif reachable == FAILURE:
            print("Cannot open TCP connection to " + self.hostname + str(self.port) + " due to non-timeout error. Is the server online?")
            return FAILURE
        elif reachable == SUCCESS:
            print("Server online. Scanning!")

        ret_09 = FAILURE
        if self.http09:
            try:
                self._debug("## Starting HTTP/0.9 analysis ##", 1)
                ret_09 = self.analyze_http09()
            except Exception as e:
                self._debug("Error while analyzing HTTP/0.9: " + str(e))
                traceback.print_exc()
                ret_09 = FAILURE
        try:
            self._debug("## Starting HTTP/1.0 analysis ##", 1)
            ret_10 = self.analyze_http10(self.redirect_depth)
        except Exception as e:
            self._debug("Error while analyzing HTTP/1.0: " + str(e))
            traceback.print_exc()
            ret_10 = FAILURE
        try:
            self._debug("## Starting HTTP/1.1 analysis ##", 1)
            ret_11 = self.analyze_http11(self.redirect_depth)
        except Exception as e:
            self._debug("Error while analyzing HTTP/1.1: " + str(e))
            traceback.print_exc()
            ret_11 = FAILURE
        try:
            self._debug("## Starting HTTP/2.0 prior knowledge analysis ##", 1)
            ret_20_prior = self.analyze_http2_prior_knowledge(self.redirect_depth)
        except Exception as e:
            self._debug("Error while analyzing HTTP/2 prior knowledge: " + str(e))
            traceback.print_exc()
            ret_20_prior = FAILURE
        try:
            self._debug("## Starting HTTP/2.0 upgrade analysis ##", 1)
            ret_20_upgrade = self.analyze_http2_upgrade(self.redirect_depth)
        except Exception as e:
            self._debug("Error while analyzing HTTP/2 upgrade: " + str(e))
            traceback.print_exc()
            ret_20_upgrade = FAILURE
        print("\n#####################\n")
        if self.http09:
            print("HTTP/0.9: " + ret_09)
        print("HTTP/1.0: " + ret_10)
        print("HTTP/1.1: " + ret_11)
        print("HTTP/2 (Prior Knowledge): " + ret_20_prior)
        print("HTTP/2 (Upgrade): " + ret_20_upgrade)

    def analyze_http09(self) -> str:
        """
        Analyzes the server for HTTP/0.9 support.
        :return: SUCCESS if HTTP/0.9 is supported, FAILURE otherwise.

        HTTP/0.9 is supported if the server responds with an HTML response.
        """
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
        if response == FAILURE or response == TIMEOUT:
            return response
        try:
            if response.lower().startswith("<html>") or response.lower().startswith("<!doctype html"):
                self._debug("HTTP/0.9 response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
                return SUCCESS
            else:
                # TODO: find better way to check for HTTP/0.9 response, maybe check for 1.0 response too?
                self._debug("Could not interpret response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") as HTTP/0.9 response.")
                return FAILURE
        except Exception as e:
            self._debug("Could not interpret response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE


    def analyze_http10(self, recursion: int) -> str:
        """
        Analyzes the server for HTTP/1.0 support.
        :param recursion: The maximum depth of redirects to follow.
        :return: SUCCESS if HTTP/1.0 is supported, FAILURE otherwise.

        HTTP/1.0 is supported if the server responds with a 200 status code.
        """
        return self.analyze_http1x("HTTP/1.0", recursion)

    def analyze_http11(self, recursion: int) -> str:
        """
        Analyzes the server for HTTP/1.1 support.
        :param recursion: The maximum depth of redirects to follow.
        :return: SUCCESS if HTTP/1.1 is supported, FAILURE otherwise.

        HTTP/1.1 is supported if the server responds with a 200 status code.
        """
        return self.analyze_http1x("HTTP/1.1", recursion)

    def analyze_http1x(self, version: str, recursion: int):
        """
        Analyzes the server for HTTP/1.x support.
        :param version: The HTTP version to analyze. Provide the complete string, e.g. "HTTP/1.0".
        :param recursion: The maximum depth of redirects to follow.
        :return: SUCCESS if HTTP/1.x is supported, FAILURE otherwise.

        HTTP/1.x is supported if the server responds with a 200 status code.
        """
        if recursion == -1:
            return MAX_REDIRECT
        # open and connect socket
        sock = self.open_socket()
        if self.connect_socket(sock) != SUCCESS:
            return FAILURE
        # send 1x request to server
        try:
            sock.send(self.create_http1x_request(version))
        except Exception as e:
            self._debug("Could not send " + version + " request to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE
        # receive response
        response = self.receive_http1x_response(sock)
        if response == FAILURE or response == TIMEOUT:
            return response
        else:
            status, headers, http_version = response
        if status == 200:
            self._debug("Received " + version + " response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
            return SUCCESS
        elif status == 301 or status == 302:
            # redirect
            # turn list of lists into dict
            redirect = self.update_redirect(dict(headers))
            if redirect != SUCCESS:
                return redirect
            return REDIRECT + "(" + self.hostname + self.path + ") -> " + self.analyze_http1x(version, recursion - 1)
        else:
            self._debug("Received status code " + str(status) + " leading to failure.")
            return FAILURE

    def analyze_http2_prior_knowledge(self, recursion: int) -> str:
        """
        Analyzes the server for HTTP/2 support with prior knowledge.
        :param recursion: The maximum depth of redirects to follow.
        :return: SUCCESS if HTTP/2 is supported, FAILURE otherwise.

        HTTP/2 with prior knowledge is supported if the server immediately responds with a 200 status code in an HTTP/2
        message.
        """
        return self.analyze_http2_core(recursion, True)


    def analyze_http2_upgrade(self, recursion: int) -> str:
        """
        Analyzes the server for HTTP/2 support with upgrade mechanism.
        :param recursion: The maximum depth of redirects to follow.
        :return: SUCCESS if HTTP/2 is supported, FAILURE otherwise.

        HTTP/2 with upgrade mechanism is supported if the server responds with a 101 status code in an HTTP/1.1 message
        and a 200 status code in an HTTP/2 message.
        """
        return self.analyze_http2_core(recursion, False)

    def analyze_http2_core(self, recursion: int, prior_knowledge: bool) -> str:
        """
        Analyzes the server for HTTP/2 support using either prior knowledge or the upgrade mechanism.
        :param recursion: The maximum depth of redirects to follow.
        :param prior_knowledge: Whether to use prior knowledge or the upgrade mechanism. True for prior knowledge,
        False for upgrade.
        :return: SUCCESS if HTTP/2 is supported, FAILURE otherwise

        This function provides the core HTTP/2 functionality. It performs the upgrade mechanism or prior knowledge and
        interprets all HTTP/2 responses in a shared loop.
        """
        if recursion == -1:
            return MAX_REDIRECT

        # open and connect socket
        sock = self.open_socket()
        if self.connect_socket(sock) != SUCCESS:
            return FAILURE
        # initialize http/2 connection
        h2_connection = h2.connection.H2Connection()

        # for prior knowledge send HTTP/2 initialization packets and then the HTTP/2 request.
        if prior_knowledge:
            # send initialization packets
            h2_connection.initiate_connection()
            try:
                sock.send(h2_connection.data_to_send())
            except Exception as e:
                self._debug("Could not initialize HTTP/2 connection to " + self.ip + ":" + str(
                    self.port) + "(" + self.hostname + ") with exception : " + str(e))
                return FAILURE
            # send http/2 request to server
            headers = [
                (':method', 'GET'),
                (':path', self.path),
                (':authority', self.hostname),
                (':scheme', 'http'),
                ('user-agent', USER_AGENT)
            ]
            h2_connection.send_headers(1, headers, end_stream=True)
            try:
                sock.send(h2_connection.data_to_send())
            except Exception as e:
                self._debug("Could not send HTTP/2 GET to " + self.ip + ":" + str(
                    self.port) + "(" + self.hostname + ") with exception : " + str(e))
                return FAILURE
            data = None

        # for upgrade mechanisms send only HTTP/1.1 request with upgrade header
        else:
            settings_header_value = h2_connection.initiate_upgrade_connection()
            try:
                sock.send(self.create_http11_upgrade_request(settings_header_value))
            except Exception as e:
                self._debug("Could not send HTTP/1.1 upgrade request to " + self.ip + ":" + str(
                    self.port) + "(" + self.hostname + ") with exception : " + str(e))
                return FAILURE
            # parse upgrade response
            response = self.receive_http2_upgrade_response(sock)
            if response == FAILURE or response == TIMEOUT:
                return response
            status_code, headers, http2_response = response

            # check for redirect
            if status_code == 301 or status_code == 302:
                # redirect
                redirect = self.update_redirect(headers)
                if redirect != SUCCESS:
                    return redirect
                return REDIRECT + "(" + self.hostname + self.path + ") -> " + self.analyze_http2_upgrade(recursion - 1)

            # check for 101 status code
            if status_code != 101:
                self._debug("Received status code " + str(status_code) + " instead of 101 during HTTP/1.1 upgrade to HTTP/2.")
                return FAILURE

            # check for upgrade header presence
            if "upgrade" not in headers:
                self._debug("No upgrade header in response to HTTP/1.1 upgrade to HTTP/2.")
                return FAILURE
            if headers["upgrade"].lower() not in ["h2c", "http/2"]:
                self._debug("Received upgrade header " + headers["upgrade"] + " instead of HTTP/2 during HTTP/1.1 upgrade to HTTP/2.")
                return FAILURE
            data = http2_response

        ##### MAIN LOOP FROM HERE ON #####

        # receive response
        finished_receiving = False
        response_received = False
        event_list = []

        # receive all data and events
        while not finished_receiving:
            try:
                # TODO: allow prior data from prior knowledge here
                if data is None:
                    data = sock.recv(BUFFER_SIZE)
            except TimeoutError:
                # can be expected, pass
                pass
            if not data:
                break
            events = h2_connection.receive_data(data)
            for event in events:
                event_list.append(event)
                if isinstance(event, h2.events.DataReceived):
                    self._debug("Received HTTP/2 data from " + self.ip + ":" + str(self.port) + "(" + self.hostname + "). Data: " + event.data.hex())
                    h2_connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    break
                if isinstance(event, h2.events.ResponseReceived):
                    self._debug("Received HTTP/2 response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + "). Response headers: " + str(event.headers))
                    # parse response_headers to dict of strings
                    try:
                        response_headers = dict([(key.decode("ASCII"), value.decode("ASCII")) for key, value in event.headers])
                    except Exception as e:
                        self._debug("Could not decode response headers from HTTP/2 response: " + str(event.headers) + " with exception: " + str(e))
                        return FAILURE
                    # analyze all received headers for success, redirect or other
                    for key, value in response_headers.items():
                        if key == ":status":
                            try:
                                status_code = int(value)
                            except Exception as e:
                                self._debug("Could not extract status code from HTTP/2 response headers: " + str(response_headers) + " with exception: " + str(e))
                                return FAILURE
                            if status_code == 200:
                                return SUCCESS
                            elif status_code == 301 or status_code == 302:
                                # redirect
                                redirect = self.update_redirect(response_headers)
                                if redirect != SUCCESS:
                                    return redirect
                                return REDIRECT + "(" + self.hostname + self.path + ") -> " + self.analyze_http2_prior_knowledge(recursion - 1)
                            else:
                                self._debug("Received status code " + str(status_code) + " leading to failure.")
                                return FAILURE
                    response_received = True
                    self._debug("Received HTTP/2 response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
                elif isinstance(event, h2.events.StreamEnded):
                    finished_receiving = True
                    break
            # send any acknowledgement
            sock.send(h2_connection.data_to_send())
            # reset data for next iteration
            data = None
        if not response_received:
            self._debug("No response received from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
            return FAILURE
        else:
            self._debug("Received response but no status header from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
            return FAILURE

    def update_redirect(self, headers: dict) -> str:
        """
        Updates the hostname and path based on a redirect response's headers.
        :param headers: The headers of the redirect response.
        :return: SUCCESS if the redirect was successful, FAILURE otherwise.

        The hostname and path are updated based on the Location header of the redirect response. Updates the object
        variables.
        """
        if "location" not in headers:
            self._debug("No location header in redirect response.")
            return FAILURE

        # dont follow https redirects
        redirect_hostname = headers["location"]
        if redirect_hostname.startswith("https://"):
            self._debug("Redirect to HTTPS site " + redirect_hostname + ", not following")
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
            # also update ip address
            if self._resolve_hostname:
                if self.resolve_hostname() == FAILURE:
                    return FAILURE
            else:
                self._debug("Not resolving hostname after redirect because static IP was given.")
        return SUCCESS

    def create_http_09_request(self) -> bytes:
        """
        Creates an HTTP/0.9 request.
        :return: The encoded HTTP/0.9 request.
        """
        return b"GET " + self.path.encode("ASCII") + b"\r\n"

    def create_http1x_request(self, version: str) -> bytes:
        """
        Creates an HTTP/1.x request.
        :param version: The HTTP version to use. Provide the complete string, e.g. "HTTP/1.0".
        :return: The encoded HTTP/1.x request.
        """
        return (
                b"GET " + self.path.encode("ASCII") + b" " + version.encode("ASCII") + b"\r\n" +
                b"Host: " + self.hostname.encode("ASCII") + b"\r\n" +
                b"User-Agent: " + USER_AGENT.encode("ASCII") + b"\r\n"
                b"Connection: close\r\n" +
                b"\r\n"
        )

    def create_http11_upgrade_request(self, settings_header_value: bytes) -> bytes:
        """
        Creates an HTTP/1.1 request to upgrade to HTTP/2. I.e., an HTTP/1.1 request with an Upgrade header.
        :param settings_header_value: The value of the HTTP2-Settings header.
        :return: The encoded HTTP/1.1 request.
        """
        return (
                b"GET " + self.path.encode("ASCII") + b" HTTP/1.1\r\n" +
                b"Host: " + self.hostname.encode("ASCII") + b"\r\n" +
                b"User-Agent: " + USER_AGENT.encode("ASCII") + b"\r\n"
                b"Connection: Upgrade, HTTP2-Settings\r\n" +
                b"Upgrade: h2c\r\n" +
                b"HTTP2-Settings: " + settings_header_value + b"\r\n" +
                b"\r\n"
        )

    def open_socket(self) -> socket.socket:
        """
        Opens a TCP socket to the server.
        :return: The opened socket.
        """
        self._debug("Opening TCP socket to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        return sock

    def connect_socket(self, sock: socket.socket) -> str:
        """
        Connects a previously opened socket to the server.
        :param sock: The socket to connect.
        :return: SUCCESS if the connection was successful, FAILURE otherwise.
        """
        try:
            sock.connect((self.ip, self.port))
        except Exception as e:
            self._debug("Could not open TCP socket to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE
        self._debug("Successfully opened TCP socket to " + self.ip + ":" + str(self.port) + "(" + self.hostname + ")")
        return SUCCESS

    def receive_bytes(self, sock: socket.socket) -> Union[bytes, str]:
        """
        Reads bytes from the socket.
        :param sock: The socket to read from.
        :return: The received bytes.

        If the response is empty, TIMEOUT is returned. If the response cannot be read, FAILURE is returned.
        """
        try:
            response = sock.recv(BUFFER_SIZE)
        except socket.timeout as e:
            self._debug("Could not receive response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return TIMEOUT
        except Exception as e:
            self._debug("Could not receive response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE
        self._debug("Received response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + "): " + response.hex())
        return response

    def decode_bytes(self, response: bytes) -> str:
        """
        Decodes bytes to an ASCII string. Returns the decoded string or FAILURE if the bytes cannot be decoded.
        :param response: The bytes to decode.
        :return: The decoded response as a string.

        If the response cannot be decoded, FAILURE is returned.
        """
        try:
            response = response.decode("ASCII")
            self._debug("Decoded response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + "): " + response)
        except Exception as e:
            self._debug("Could not decode response from " + self.ip + ":" + str(self.port) + "(" + self.hostname + ") with exception : " + str(e))
            return FAILURE
        return response

    def receive_ascii_response(self, sock: socket.socket, header_only: bool=False) -> str:
        """
        Reads bytes from the socket and returns them as an ASCII string.
        :param sock: The socket to read from.
        :param header_only: Whether to only read the header of the response. (default: False)
        :return: The ASCII response as a string.

        If the response is empty, TIMEOUT is returned. If the response cannot be read, FAILURE is returned.
        """
        response = self.receive_bytes(sock)
        if response == FAILURE or response == TIMEOUT:
            return response
        if header_only:
            # discard everything except the header
            if not b"\r\n\r\n" in response:
                self._debug("No \\r\\n\\r\\n separator between HTTP/1.x response header and body or request end.")
                return FAILURE
            response = response.split(b"\r\n\r\n")[0] + b"\r\n\r\n"
        return self.decode_bytes(response)

    def parse_http1_response(self, response: str) -> Union[Tuple[int, dict, str], str]:
        """
        Parses an HTTP/1.x response. Extracts status code, headers, and HTTP version.
        :param response: The response to parse.
        :return: The status code, headers, and HTTP version as a tuple.

        The response is expected to be a valid HTTP/1.x response.
        """
        try:
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
            self._debug("Extracted Status code: " + str(status) + ", Headers: " + str(headers) + ", HTTP version: " + http_version)
        except Exception as e:
            self._debug("Failed to parse HTTP/1 response: " + response + " with exception: " + str(e))
            return FAILURE
        return status, headers, http_version

    def receive_http1x_response(self, sock: socket.socket) -> (int, dict, str):
        """
        Receives an HTTP/1.x response from the server. Parses the response and returns the status code, headers, and
        HTTP version.
        :param sock: The socket to receive the response from.
        :return: The status code, headers, and HTTP version as a tuple.

        If the response is empty, TIMEOUT is returned. If the response cannot be parsed, FAILURE is returned. Merges
        the functionality of receive_ascii_response and parse_http1_response.
        """
        response = self.receive_ascii_response(sock, header_only=True)
        if response == FAILURE or response == TIMEOUT:
            return response
        # extract status code, headers and http version
        parsed_response = self.parse_http1_response(response)
        if parsed_response == FAILURE:
            return FAILURE
        else:
            return parsed_response

    def receive_http2_upgrade_response(self, sock: socket.socket) -> Union[Tuple[int, dict, bytes], str]:
        """
        Receives an HTTP/1.x response with status code 101 from the server. Parses the 101 response and returns its
        status code and headers and the subsequent HTTP/2 response.
        :param sock: The socket to receive the response from.
        :return: The HTTP/2 response as bytes.

        If the response is empty, TIMEOUT is returned. If the response cannot be parsed, FAILURE is returned.
        """
        response = self.receive_bytes(sock)
        if response == FAILURE or response == TIMEOUT:
            return response

        # require \r\n\r\n to separate HTTP/1.1 and HTTP/2 response
        if b"\r\n\r\n" not in response:
            self._debug("No separator between HTTP/1.1 and HTTP/2 response.")
            return FAILURE

        # extract HTTP/1.1 and HTTP/2 response
        http1_response, http2_response = response.split(b"\r\n\r\n", 1)
        http1_response += b"\r\n\r\n"
        self._debug("Extracted HTTP/1.1 response: " + http1_response.hex() + ", HTTP/2 response: " + http2_response.hex())
        self._debug("Extracted HTTP/2 response: " + http2_response.hex())

        # parse HTTP/1 response as ASCII
        http1_response = self.decode_bytes(http1_response)
        if http1_response == FAILURE:
            return FAILURE
        # extract status code, headers and http version
        http1_response = self.parse_http1_response(http1_response)
        if http1_response == FAILURE:
            return FAILURE
        status_code, headers, _ = http1_response

        return status_code, headers, http2_response

    def resolve_hostname(self):
        """
        Resolves the hostname to an IP address. Returns FAILURE if the hostname cannot be resolved. Set the object
        variable ip to the resolved IP address.
        """
        try:
            self.ip = socket.gethostbyname(self.hostname)
            self._debug("Resolved hostname " + self.hostname + " to IP: " + self.ip)
        except Exception as e:
            self._debug("Failed to resolve hostname " + self.hostname + " with Exception: " + str(e))
            return FAILURE

    def analyze_tcp_reachability(self) -> str:
        """
        Analyzes the server for TCP reachability. Opens a TCP socket to the server. Returns SUCCESS if the server is
        reachable, FAILURE otherwise. Returns TIMEOUT if the server is not reachable due to a timeout.
        """
        # open tcp socket to ip
        sock = self.open_socket()
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

    def _debug(self, string: str, linebreaks: int=0):
        """
        Prints a debug message if debug is enabled.
        :param string: The debug message to print.
        """
        if self.debug:
            print(linebreaks * "\n" + "DEBUG:" + string)

# start main method
if __name__ == '__main__':
    main()