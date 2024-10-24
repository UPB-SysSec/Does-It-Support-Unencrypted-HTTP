import socket

SUCCESS = "SUCCESS"
FAILURE = "FAILURE"
TIMEOUT = "TIMEOUT"

def main():
    # do command line stuff
    # max redirect follows, debug, and analyzed server
    # optional ip
    # TODO: fill with values
    Analyzer().analyze()

class Analyzer:
    def __init__(self, hostname: str, ip: str = None, port: int =  80, debug: bool = False, redirect_depth: int = 1, timeout: int = 5):
        self.hostname = hostname
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


        # check for HTTP 0.9 reachability
        analyze_http09()
        analyze_http10()
        analyze_http11()
        analyze_http2_prior_knowledge()
        analyze_http2_upgrade()
        print("results")
        # analyze server for raw http support

    def analyze_http09(self) -> str:
        # send 09 request (no headers), check if 200 response
        # call recursively if redirect to other http site

    def analyze_http10(self) -> str:
        # send 10 request, check if 200 response
        # call recursively if redirect to other http site

    def analyze_http11(self) -> str:
        # send 11 request, check if 200 response
        # call recursively if redirect to other http site

    def analyze_http2_prior_knowledge(self) -> str:
        # send http 2 request and check if 200 response
        # call recursively if redirect to other http site

    def analyze_http2_upgrade(self) -> str:
        # send http1 upgrade, check if 101 response, and if yes check if following http/2 is returned 200
        # call recursively if redirect to other http site

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
            print(string)

if __name__ == '__main__':
    main()