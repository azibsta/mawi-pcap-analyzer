import os
import sys
import webbrowser
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# Serve the parent directory so /reports and /frontend are both accessible
ROOT_DIR = Path(__file__).parent.parent
PORT = 8000

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

def run_server():
    os.chdir(ROOT_DIR)
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, CORSRequestHandler)
    print(f"Server running at http://localhost:{PORT}/frontend/")
    httpd.serve_forever()

if __name__ == '__main__':
    # Start the server in a separate thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Wait a tiny bit for the server to bind
    time.sleep(1)
    
    # Open the browser
    url = f"http://localhost:{PORT}/frontend/index.html"
    print(f"Opening browser to {url} ...")
    webbrowser.open(url)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down server.")
        sys.exit(0)
