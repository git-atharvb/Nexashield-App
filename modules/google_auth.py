import webbrowser
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from PyQt6.QtCore import QThread, pyqtSignal

# ==========================================
# GOOGLE AUTH WORKER
# ==========================================

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Handles the callback from Google after user logs in."""
    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/callback":
            query = parse_qs(parsed_path.query)
            if 'code' in query:
                self.server.auth_code = query['code'][0]
                
                # Send a nice response to the browser
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                html = """
                <html><body style="font-family: sans-serif; text-align: center; background-color: #2b2b2b; color: white; padding-top: 50px;">
                    <h1>Login Successful</h1>
                    <p>You can close this window and return to NexaShield.</p>
                    <script>window.close()</script>
                </body></html>
                """
                self.wfile.write(html.encode('utf-8'))
            elif 'error' in query:
                self.server.auth_error = query['error'][0]
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                html = f"""
                <html><body style="font-family: sans-serif; text-align: center; background-color: #2b2b2b; color: white; padding-top: 50px;">
                    <h1>Login Failed</h1>
                    <p>Error: {self.server.auth_error}</p>
                    <p>You can close this window and return to NexaShield.</p>
                </body></html>
                """
                self.wfile.write(html.encode('utf-8'))
            else:
                self.send_error(400, "Authorization code not found")
        else:
            self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        pass  # Suppress console logging

class GoogleAuthWorker(QThread):
    auth_success = pyqtSignal(dict)  # Returns user info (email, name, picture)
    auth_error = pyqtSignal(str)

    def __init__(self, client_id, client_secret):
        super().__init__()
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_port = 0
        self.redirect_uri = ""

    def run(self):
        try:
            # 1. Start Local Server to listen for the callback on an available port
            server = HTTPServer(('127.0.0.1', 0), OAuthCallbackHandler)
            self.redirect_port = server.server_port
            self.redirect_uri = f"http://127.0.0.1:{self.redirect_port}/callback"
            server.auth_code = None
            server.auth_error = None

            # 2. Construct Auth URL
            auth_url = (
                f"https://accounts.google.com/o/oauth2/auth?"
                f"response_type=code&client_id={self.client_id}&"
                f"redirect_uri={self.redirect_uri}&"
                f"scope=openid%20email%20profile%20https://www.googleapis.com/auth/drive.readonly"
            )

            # 3. Open System Browser
            webbrowser.open(auth_url)

            server.timeout = 1.0  # 1 second timeout
            timeout_counter = 0
            max_timeout = 90  # Wait up to 90 seconds

            while not server.auth_code and not server.auth_error and timeout_counter < max_timeout:
                server.handle_request()
                timeout_counter += 1

            if not server.auth_code and not server.auth_error:
                self.auth_error.emit("Authentication timed out or was cancelled by closing the browser.")
                server.server_close()
                return

            if server.auth_error:
                self.auth_error.emit(f"Authentication Error: {server.auth_error}")
                server.server_close()
                return

            # 5. Exchange Code for Access Token
            token_data = {
                'code': server.auth_code,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'redirect_uri': self.redirect_uri,
                'grant_type': 'authorization_code'
            }
            
            response = requests.post("https://oauth2.googleapis.com/token", data=token_data)
            tokens = response.json()

            if 'access_token' in tokens:
                # 6. Fetch User Info
                user_info_resp = requests.get(
                    "https://www.googleapis.com/oauth2/v1/userinfo",
                    headers={'Authorization': f"Bearer {tokens['access_token']}"}
                )
                user_info = user_info_resp.json()
                user_info['access_token'] = tokens['access_token']
                self.auth_success.emit(user_info)
            else:
                self.auth_error.emit(f"Failed to retrieve access token: {tokens.get('error', 'Unknown error')}")

            server.server_close()

        except Exception as e:
            self.auth_error.emit(f"Authentication Error: {str(e)}")