from http.server import HTTPServer, SimpleHTTPRequestHandler

class Handler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
