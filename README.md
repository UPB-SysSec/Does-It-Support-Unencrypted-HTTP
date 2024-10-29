# Raw-HTTP-Support-Analyzer
Analyzes a server for unencrypted HTTP support for version HTTP/0.9 to HTTP/2.

Execute the script with a host as an argument. It tells you the unencrypted HTTP/2 versions supported by the server.

## Requirements
- Python 3
  - Supported versions: 3.9, 3.10, 3.11, 3.12, 3.13
  - https://www.python.org/downloads/
- h2 (https://pypi.org/project/h2/)
  - Install with `pip3 install h2` or `pip3 install -r requirements.txt`
- docker (if you want to run the script inside a container)
  - https://docs.docker.com/engine/install/

## Usage
```
usage: analyze.py [options]

Analyzes servers for unencrypted HTTP support.

positional arguments:
  hostname              The hostname of the server to analyze

options:
  -h, --help            show this help message and exit
  --path PATH           The path to request from the server (default: /)
  --ip IP               The IP of the server to analyze. If not provided, the hostname is resolved. If present, prevents domain resolution after redirects. (default: None)
  --port PORT           The port of the server to analyze (default: 80)
  --http09, --no-http09
                        By default, HTT/0.9 is not analyzed. Provide --http09 to analyze the server for HTT/0.9 support. Return Type of HTT/0.9 probe is inconclusive, so run with debug or external analysis tool like Wireshark to verify the actual server answer. (default: False)
  --debug, --no-debug   Whether to print debug output (default: False)
  --redirect_depth REDIRECT_DEPTH
                        The maximum depth of redirects to follow (default: 2)
  --timeout TIMEOUT     The timeout for socket operations (default: 5)
```

## Example output

`python3 analyze.py lgbtchinatour.com`

```
lgbtchinatour.com analysis started.
Server online. Scanning!

#####################

HTTP/1.0: REDIRECT(www.lgbtchinatour.com/) -> SUCCESS
HTTP/1.1: SUCCESS
HTTP/2 (Prior Knowledge): FAILURE
HTTP/2 (Upgrade): FAILURE
```

## Return Types
### SUCCESS
The server supports the version of HTTP. For HTTP/0.9, the server responded with HTML.
For HTML/1.0 and HTTP/1.1 the server responded with a 200 status code.
For HTTP/2 with prior knowledge, the server responded with a 200 status code in an HTTP/2 response.
For HTTP/2 with upgrade, the server responded with a 101 status code in an HTTP/1.1 response and then a 200 status code 
in an HTTP/2 response.

### FAILURE
The server does not support the version of HTTP. Run with `--debug` to see detailed analysis and server responses.

### TIMEOUT
The server did not respond within the specified timeout. The timeout is specified with `--timeout` (default: 5s).

### MAX REDIRECT
The server redirected too many times. The maximum number of redirects is specified with `--redirect_depth` (default: 5).

### REDIRECT
The server redirected to another location. The location is specified alongside this feedback. Multiple redirects are
chained in the output.

### HTTPS REDIRECT
The server redirected to an HTTPS location. The server does not support unencrypted HTTP.

## Docker
The script can be run inside a Docker container. The Dockerfile is included in the repository.

To run the script inside a container, build the image with
```
docker build -t raw-http-support-analyzer .
```
and run the script using 
```
docker run raw-http-support-analyzer <arguments>
```
for example
```
docker run raw-http-support-analyzer nsfwyoutube.com --debug --timeout 10
```

### HTTP/0.9 Support
Currently, the tool checks unencrypted HTTP/0.9 support by detecting whether the server answered with HTML content. It
is possible that the tool outputs a false positive if the server responds with HTML content that does not serve the 
requested website. For instance, the server could host a default page that is served for all requests. For the detailed 
server response, run the tool with the `--debug` flag.

### Acknowledgements
This tool is based on code written by Jonathan von Niessen (https://github.com/jonvn) for his master thesis.