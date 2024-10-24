import argparse
import asyncio
import json
import os
import time
from datetime import datetime

import aiofiles
import h2.connection
import pandas as pd

from base import BASE_DIR
from utility.setup_logger import setup_logger

OUTPUT_FILE = os.path.join(BASE_DIR, "http2_support_scanner/results/results.jsonl")
CONCURRENCY_LIMIT = 50
CHUNK_SIZE = 10000
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 10
SEM = asyncio.Semaphore(CONCURRENCY_LIMIT)
logger = setup_logger("HTTP/2 Upgrade Scanner", "http2_support_scanner.log")


class ConnectionManager:
    """
    Manages the establishment and closure of a network connection to a host on port 80.
    """

    def __init__(self, host):
        self.host = host
        self.reader = None
        self.writer = None

    async def __aenter__(self):
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, 80), timeout=CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            raise ConnectionError("Connect timed out")
        except Exception as e:
            raise ConnectionError(f"Could not establish connection: {e}")
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        try:
            await self.close()
        except Exception as e:
            pass  # Ignore exceptions related to closing a connection

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()


async def send_data(writer, data):
    try:
        writer.write(data)
        await writer.drain()
    except Exception as e:
        raise RuntimeError(f"Failed to send data: {e}")


async def read_response(reader, delimiter=None):
    try:
        if delimiter is None:
            return await asyncio.wait_for(reader.read(65536), timeout=READ_TIMEOUT)
        else:
            return await asyncio.wait_for(reader.readuntil(delimiter), timeout=READ_TIMEOUT)
    except asyncio.TimeoutError:
        raise ConnectionError("Read timed out")
    except Exception as e:
        raise RuntimeError(f"Failed to read response: {e}")


def parse_http1_response(response):
    """
    Helper function for parsing HTTP/1 responses

    :param response: The encoded HTTP response
    :return: The status code, headers, and HTTP version
    """
    try:
        response = response.decode()
        response_lines = response.split('\r\n')
        status_line = response_lines[0]
        headers = {}
        for line in response_lines[1:]:
            if line == '':
                break

            key, value = line.split(':', 1)
            key = key.strip()
            headers[key] = value.strip()

        status = int(status_line.split(' ')[1])
        http_version = status_line.split(' ')[0].split('/')[1]
        return status, headers, http_version
    except Exception as e:
        raise RuntimeError(f"Failed to parse HTTP/1 response: {e}: '{response}'")


async def handle_http2_response(h2_connection, reader, writer, is_new_connection=True):
    """
    Helper function for handling HTTP/2 responses

    :param h2_connection: h2 connection object
    :param reader: reader object for the connection
    :param writer: writer object for the connection
    :param is_new_connection: flag indicating if the connection is new or not (needed for subsequent request)
    :return: Status code and events from the HTTP/2 response or error
    """
    response_headers = None
    response_stream_ended = False
    response_received = False
    event_list = []

    await send_data(writer, h2_connection.data_to_send())

    while not response_stream_ended:
        try:
            data = await read_response(reader)
            if not data:
                if is_new_connection:  # Simultaneously is_first_frame because is set to false in the first iteration
                    raise RuntimeError(f"Received no data")
                break

            events = h2_connection.receive_data(data)

            if is_new_connection:
                if len(events) == 0:
                    raise RuntimeError(f"Received unexpected data instead of a SETTINGS frame")
                if not isinstance(events[0], h2.events.RemoteSettingsChanged):
                    raise RuntimeError(f"First frame has to be a SETTINGS frame")
            is_new_connection = False

            for event in events:
                event_list.append(str(event))
                if isinstance(event, h2.events.DataReceived):
                    h2_connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                if isinstance(event, h2.events.ResponseReceived):
                    response_received = True
                    response_headers = event.headers
                if isinstance(event, h2.events.StreamEnded):
                    response_stream_ended = True
                    break

            await send_data(writer, h2_connection.data_to_send())
        except h2.connection.ProtocolError as e:
            raise RuntimeError(
                f"Failed to process HTTP/2 response: {type(e).__name__}({e})")  # The type is important to see which Protocol Error occurred
        except Exception as e:
            raise RuntimeError(f"Failed to process HTTP/2 response: {e}")

    # The ResponseReceived event is fired when a response header is received. If it's missing we assume no support
    if not response_received:
        return {
            "Error": "Did not get ResponseReceived event",
            "Events": event_list
        }

    try:
        status_code = int(response_headers[0][1])
    except Exception as e:
        return {
            "Error": "Could not parse status code", "Details": str(e),
            "Events": event_list
        }

    return {
        "Status": status_code,
        "Events": event_list
    }


async def fetch_http1_get(host, path="/"):
    try:
        async with ConnectionManager(host) as conn:
            request = (
                    b"GET " + path.encode() + b" HTTP/1.1\r\n" +
                    b"Host: " + host.encode() + b"\r\n" +
                    b"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0\r\n"
                    b"Connection: close\r\n" +
                    b"\r\n"
            )

            await send_data(conn.writer, request)
            response = await read_response(conn.reader, b"\r\n\r\n")
            status, headers, http_version = parse_http1_response(response)

            return {
                "Status": status,
                "Headers": headers,
                "HTTP version": http_version
            }
    except Exception as e:
        return {
            "Error": str(e)
        }


async def fetch_direct_http2(host, path="/"):
    try:
        async with ConnectionManager(host) as conn:
            h2_connection = h2.connection.H2Connection()
            h2_connection.initiate_connection()
            await send_data(conn.writer, h2_connection.data_to_send())

            headers = [
                (':method', 'GET'),
                (':path', path),
                (':authority', host),
                (':scheme', 'http'),
                ('user-agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0')
            ]
            h2_connection.send_headers(1, headers, end_stream=True)
            await send_data(conn.writer, h2_connection.data_to_send())
            response = await handle_http2_response(h2_connection, conn.reader, conn.writer)
        return response
    except Exception as e:
        return {
            "Error": str(e)
        }


async def fetch_upgrade(host, path="/"):
    # Craft Upgrade request
    h2_connection = h2.connection.H2Connection()
    settings_value = h2_connection.initiate_upgrade_connection()
    request = (
            b"GET " + path.encode() + b" HTTP/1.1\r\n" +
            b"Host: " + host.encode() + b"\r\n" +
            b"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0\r\n"
            b"Connection: Upgrade, HTTP2-Settings\r\n" +
            b"Upgrade: h2c\r\n" +
            b"HTTP2-Settings: " + settings_value + b"\r\n" +
            b"\r\n"
    )

    try:
        async with ConnectionManager(host) as conn:
            try:
                await send_data(conn.writer, request)
                response = await read_response(conn.reader, b'\r\n\r\n')
                status, headers, http_version = parse_http1_response(response)

                upgrade_response = {
                    "Status": status,
                    "Headers": headers,
                    "HTTP version": http_version
                }
            except Exception as e:
                return {"Result of Upgrade request": {"Error": str(e)}}

            # A status != 101 means that the host doesn't support the Upgrade mechanism
            if status != 101:
                return {"Result of Upgrade request": upgrade_response}

            # Continue if status code was 101
            try:
                try:
                    http2_response = await handle_http2_response(h2_connection, conn.reader, conn.writer)
                except Exception as e:
                    return {
                        "Result of Upgrade request": upgrade_response,
                        "HTTP/2 response": {"Error": str(e)}
                    }

                # Send subsequent request
                headers = [
                    (':method', 'GET'),
                    (':path', '/'),
                    (':authority', host),
                    (':scheme', 'http'),
                ]
                next_stream_id = h2_connection.get_next_available_stream_id()
                h2_connection.send_headers(next_stream_id, headers, end_stream=True)
                await send_data(conn.writer, h2_connection.data_to_send())
                subsequent_request_result = await handle_http2_response(h2_connection, conn.reader, conn.writer,
                                                                        is_new_connection=False)
            except Exception as e:
                return {
                    "Result of Upgrade request": upgrade_response,
                    "HTTP/2 response": http2_response,
                    "Result of subsequent request": {"Error": str(e)}
                }

            return {
                "Result of Upgrade request": upgrade_response,
                "HTTP/2 response": http2_response,
                "Result of subsequent request": subsequent_request_result
            }
    except Exception as e:
        return {
            "Error": str(e)
        }


async def scan_domain(domain):
    """
    Probe the given domain name by calling the functions to send all three scan vectors

    :param domain: the domain name to probe
    :return: {domain: {
                    "Basic GET": {"Status": int, "Headers": dict, "HTTP version": string},
                    "Upgrade -> HTTP/2": {
                        "Result of Upgrade request": {"Status": int, "Headers": dict, "HTTP version": string},
                        "HTTP/2 response": {"Status": int, "Events": list}
                        "Result of subsequent request": {"Status": int, "Events": list}
                    "HTTP/2 Prior Knowledge": {"Status": int, "Events": list}
                    }
            }
    """
    async with SEM:  # Semaphore limits number of domains that are scanned at the same time
        results = {}
        tasks = [
            fetch_http1_get(domain),
            fetch_upgrade(domain),
            fetch_direct_http2(domain)
        ]
        responses = await asyncio.gather(*tasks)  # Wait for the results

        results[domain] = {
            "Basic GET": responses[0],
            "Upgrade -> HTTP/2": responses[1],
            "HTTP/2 Prior Knowledge": responses[2]
        }
        return results


async def measure_unencrypted_http_support(domains):
    """
    Starts the scanning process. Results are written to file as soon as they are available.

    :param domains: list of domains to scan
    :return: writes a file with results to specified path
    """
    tasks = [scan_domain(domain) for domain in domains]

    async with aiofiles.open(OUTPUT_FILE, mode='a') as out_file:
        for future in asyncio.as_completed(tasks):
            try:
                result = await future
                await out_file.write(json.dumps(result) + "\n")  # Write JSON string to file
            except Exception as e:
                logger.error(f"An error occurred when writing to output file:\n{result}\n{e}")  # Shouldn't occur


def main(file_path, column_index, has_header_row, is_production_mode):
    """
    See README.md for usage instructions
    """
    start_time = time.time()
    logger.info(f"Program started at {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')}")

    logger.info(f"Using file {file_path}")
    file_path = os.path.join(BASE_DIR, file_path)
    # Ensure that last results aren't accidentally overwritten
    if os.path.exists(OUTPUT_FILE):
        if is_production_mode:
            raise FileExistsError(f"The output file '{OUTPUT_FILE}' already exists.")
        else:
            os.remove(OUTPUT_FILE)

    header = 0 if has_header_row else None
    reader = pd.read_csv(file_path, usecols=[column_index], chunksize=CHUNK_SIZE, header=header)
    loop = asyncio.get_event_loop()
    for chunk_index, chunk in enumerate(reader):  # Use chunks for performance reasons and for progress tracking
        lap_start_time = time.time()
        domains = chunk.iloc[:, 0].tolist()
        loop.run_until_complete(measure_unencrypted_http_support(domains))
        lap_time = time.time() - lap_start_time
        lap_minutes, lap_seconds = divmod(lap_time, 60)
        elapsed_time = time.time() - start_time
        elapsed_hours, elapsed_minutes = divmod(elapsed_time, 3600)
        elapsed_minutes = elapsed_minutes // 60
        logger.info(
            f"Processed {(chunk_index + 1) * CHUNK_SIZE} domains. "
            f"Lap time {lap_minutes:.0f}:{lap_seconds:02.0f} (MM:SS). "
            f"Elapsed time {elapsed_hours:.0f}:{elapsed_minutes:02.0f} (HH:MM)."
        )
    loop.close()

    end_time = time.time()
    logger.info(f"Program finished at {datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')}")
    duration = end_time - start_time
    minutes, seconds = divmod(duration, 60)
    logger.info(f"Scan took: {minutes:.0f}:{seconds:02.0f} (MM:SS)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the HTTP/2 Upgrade Support Scanner")

    parser.add_argument("--file_path", type=str, default="http2_support_scanner/test_lists/tranco_KJWPW.csv",
                        help="Path to the csv file (relative to Code/)"
                             "(default: http2_support_scanner/test_lists/tranco_KJWPW.csv)")
    parser.add_argument("--has_header_row", action='store_true',
                        help="Use this flag if there is a header row in the CSV file")
    parser.add_argument("--column_index", type=int, default=1,
                        help="Index of column with domain names (0-based) (default: 1)")
    parser.add_argument("--is_production_mode", action='store_true',
                        help="Use this flag if used in production")

    args = parser.parse_args()

    main(args.file_path, args.column_index, args.has_header_row, args.is_production_mode)
