#!/usr/bin/env python3
"""
Simple test HTTP server for demonstrating HarbingerDAST
"""
from http.server import HTTPServer, BaseHTTPRequestHandler

class TestHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', 'TestServer/1.0')  # Information disclosure
        self.end_headers()
    
    def do_GET(self):
        # Intentionally missing security headers for demonstration
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', 'TestServer/1.0')  # Information disclosure
        # Missing security headers: X-Frame-Options, X-Content-Type-Options, etc.
        self.end_headers()
        
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Test Application</title></head>
        <body>
            <h1>Test Web Application</h1>
            <p>This is a test application for HarbingerDAST scanning.</p>
        </body>
        </html>
        """
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        # Suppress logs
        pass

if __name__ == '__main__':
    port = 8080
    server = HTTPServer(('localhost', port), TestHandler)
    print(f"Test server running on http://localhost:{port}")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")
