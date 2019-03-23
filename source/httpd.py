#! /usr/bin/env python
# -*- coding: utf-8 -*-
import asynchat
import asyncore
import datetime
import errno
import logging
import os
import urllib2
import mimetypes

from optparse import OptionParser
from socket import *


DEFAULT_DOCUMENT_ROOT = r'./'
OK = 200
FORBIDDEN = 403
NOT_FOUND = 404
NOT_ALLOWED = 405
CRLF = "\r\n"

CODES = {
    OK: "OK",
    FORBIDDEN: "FORBIDDEN",
    NOT_FOUND: "NOT FOUND",
    NOT_ALLOWED: "METHOD NOT ALLOWED",
}

MIME = {
        '.html': 'text/html',
        '.css': 'text/css',
        '.js': 'text/javascript',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.swf': 'application/x-shockwave-flash',
    }

MAXLINE = 1024
config = {
    "HTTPD": 'http:/'#/127.0.0.1:8080"
}


class HttpResponse(object):
    def __init__(self, code, content_type=None, content_len=0):
        self.code = code
        self.content_type = content_type
        self.content_len = content_len
        self.utc = datetime.utcnow()

    def headers_form(self):
        headers = ["HTTP/1.1 {0} {1}".format(self.code, CODES[self.code]),
                   self.utc.strftime("Date: %a, %d %b %Y %H:%M:%S GMT"), "Server: OTUServer/1.0"]
        if self.content_len is not None:
            headers.append("Content-Length: %d" % self.content_len)
        if self.content_type:
            headers.append("Content-Type: %s" % self.content_type)
        #if self.conn_state:
           # headers.append("Connection: %s" % self.conn_state)

        return CRLF.join(headers)


def form_response(req, root_dir):
    filename = root_dir #+...
    logging.info("checking the local file %s", filename)

    if not os.path.isfile(root_dir):
        logging.info("file doesn't exist")
        return HttpResponse(NOT_FOUND, None)
    if not os.access(root_dir, os.R_OK):
        logging.info("... access denied")
        return HttpResponse(FORBIDDEN, None)

    content_type = MIME[filename]  #mimetypes.guess_type(filename)
    content_len = os.stat(filename).st_size
    if req.method == "GET":
        return HttpResponse(OK, content_type, content_len)
    elif req.method == "HEAD":
        return HttpResponse(OK, content_type, content_len)
    else:
        return HttpResponse(NOT_ALLOWED, None)


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


class HttpRequest(object):
    def __init__(self, method, fpath, version, headers):
        self.method = method
        self.version = version
        self.headers = headers
        self.rel_path = fpath
        logging.info("Created %s", self)

    def __str__(self):
        return ("HttpRequest: {method}, {version}, {headers}, {path)".
                format(method=self.method, version = self.version, headers=self.headers, path=self.rel_path))

    def read_request(self, data):
        lines = str(data).split(CRLF)
        method, location, version = lines[0].split()
        headers = {}
        for s in lines[1:]:
            header, value = s.split(": ", 1)
            headers[header] = value
        return HttpRequest(
            method,
            location,
            version,
            headers
        )


class RequestHandler(asynchat.async_chat):
    def __init__(self, sock, addr, root_dir):
        asynchat.async_chat.__init__(self, sock=sock)
        self.root_dir = root_dir
        self.buffer = []
        self.set_terminator(CRLF + CRLF)
        self.logger = logging.getLogger("handling req from %s" % (addr,))

    def collect_incoming_data(self, data):
        self.logger.info("collect incoming data", data)
        self.buffer.append(data)

    def found_terminator(self):
        req = HttpRequest.read_request(self.buffer)
        resp = form_response(req, self.root_dir)
        download(req.rel_path, self.root_dir, config['HTTPD'])
        self.push(resp.headers_form())


class WebServer(asyncore.dispatcher):
    def __init__(self, config, options, host, port):
        self.httpd_base_url = config["HTTPD"]
        self.workers_number = options.workers
        self.doc_dir = options.root

        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(host, port)
        self.listen(100)

    def handle_accept(self):
        listening = self.accept()
        if listening is not None:
            client_sock, address = listening
            logging.info('Accepted connection from {}'.format(repr(address)))
            RequestHandler(client_sock, address, self.doc_dir)

def main():
    op = OptionParser()
    op.add_option("-w", "--workers", action="store", type=int, default=10)
    op.add_option("-r", "--root", action="store", type="string", default=DEFAULT_DOCUMENT_ROOT)
    (opts, args) = op.parse_args()

    logging.basicConfig(format='%(asctime)s %(levelname)s %(processName)s %(threadName)s %(message)s',
                        level=logging.INFO)

    try:
        server = WebServer(config, opts)
        asyncore.loop()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
