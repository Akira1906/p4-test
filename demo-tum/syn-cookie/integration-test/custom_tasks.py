import http.server
import socketserver

def start_http_server(port=8081):
    """Starts a simple HTTP server (blocking mode)."""
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"🚀 HTTP Server running on port {port}...")
        httpd.serve_forever()  # This blocks execution