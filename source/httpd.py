#! /usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import sys
import threading
import urlparse
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import urllib2

import time
from optparse import OptionParser
from socket import *
from Queue import Queue

DEFAULT_DOCUMENT_ROOT = r'./'

CODES = {
    200: "OK",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD NOT ALLOWED"
}
MAXLINE = 1024
config = {
    "HTTPD": 'http:/'#/127.0.0.1:8080"
}


class LineTooLong(Exception):
    def __init__(self, message):
        self.message = message


class BadStatusLine(Exception):
    def __init__(self, message):
        self.message = message


class HTTPResponse:

    def __init__(self, sock, debuglevel=0, strict=0, method=None, buffering=False):
        if buffering:
            # The caller won't be using any sock.recv() calls, so buffering
            # is fine and recommended for performance.
            self.fp = sock.makefile('rb')
        else:
            # The buffer size is specified as zero, because the headers of
            # the response are read with readline().  If the reads were
            # buffered the readline() calls could consume some of the
            # response, which make be read via a recv() on the underlying
            # socket.
            self.fp = sock.makefile('rb', 0)
        self.debuglevel = debuglevel
        self.strict = strict
        self._method = method

        self.msg = None

    def read_request(self):
        # Initialize with Simple-Response defaults
        line = self.fp.readline(MAXLINE + 1)
        if len(line) > MAXLINE:
            raise LineTooLong("header line")
        if self.debuglevel > 0:
            print "reply:", repr(line)
        if not line:
            # Presumably, the server closed the connection before
            # sending a valid response.
            raise BadStatusLine(line)
        try:
            print "line is:", line
            [method, URI, version] = line.split(None, 2)
        except ValueError:
            method, URI, version = "", "", ""
        return method, URI, version


def download(URI, path, httpd_base_url, timeout=40):
    url = httpd_base_url + URI
    print "url is:", url
    print "...Requesting %s" % url
    request = urllib2.urlopen(url, timeout=timeout)
    headers = request.info()
    code = request.getcode()
    size = -1
    if "content-length" in headers:
        size = int(headers["content-length"])
    chunk_size = 1024 * 1024
    read = 0
    with open(path, "w") as fp:
        while True:
            chunk = request.read(chunk_size)
            if not chunk:
                break
            fp.write(chunk)
            read += len(chunk)
    if size > 0 and read < size:
        raise ValueError("Retrieval incomplete: got only %s out of %s bytes" % (read, size))
    return code


class WebServer(object):
    def __init__(self, config, options):
        self.httpd_base_url = config["HTTPD"]
        self.workers_number = options.workers
        self.documents_dir = options.root
        self.q = Queue(maxsize=0)
        self.bind_ip = 'localhost'
        self.bind_port = 8080
        self.server_sock = socket(AF_INET, SOCK_STREAM)
        self.server_sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        self.server_sock.bind((self.bind_ip, self.bind_port))
        self.server_sock.listen(5)
        print 'Listening on {}:{}'.format(self.bind_ip, self.bind_port)

    def handle_client_connection(self, queue):
        while not queue.empty():
            client_socket = queue.get()  # fetch new work from the Queue
            try:
                clients_request = HTTPResponse(client_socket)
                print 'Received {}'.format(clients_request)
                method, uri, version = clients_request.read_request()
                if not method: break

                if method == "GET" or method == "HEAD":
                    _, filename = os.path.split(uri)
                    path = os.path.join(os.path.dirname(self.documents_dir), "{0}{1}".format(filename, ".html"))
                    code = download(uri, path, config["HTTPD"])
                    if code in CODES:
                        print "I send"
                        request = version + " " + repr(code) + " " + CODES[code]
                        client_socket.sendall(bytes(request))
                else:
                    request = version + " " + "405" + CODES.get(405)
                    client_socket.sendall(bytes(request))

                client_socket.close()
                queue.task_done()
            except:
                print "Unexpected error with URL:", sys.exc_info()

        return True

    def requests_handler(self):
        while True:
            for i in range(self.workers_number):
                client_sock, address = self.server_sock.accept()
                print 'Accepted connection from {}:{}'.format(address[0], address[1])
                self.q.put(client_sock)
                print 'Starting thread ', i
                worker = threading.Thread(
                    target=self.handle_client_connection,
                    args=(self.q,)
                )
                worker.setDaemon(True)
                worker.start()
            # now we wait until the queue has been processed
            self.q.join()
            print 'All tasks completed.'


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-w", "--workers", action="store", type=int, default=1)
    op.add_option("-r", "--root", action="store", type="string", default=DEFAULT_DOCUMENT_ROOT)
    (opts, args) = op.parse_args()

    try:
        server = WebServer(config, opts)
        server.requests_handler()
    except KeyboardInterrupt:
        pass
