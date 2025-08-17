# auth_manager.py - Enhanced Authentication Manager with MongoDB
from PyQt5.QtCore import QObject, pyqtSignal
import google.oauth2.credentials
import google_auth_oauthlib.flow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import requests
import json
import os
from datetime import datetime
import pymongo
from pymongo import MongoClient
import hashlib

class AuthManager(QObject):
    # Signals
    login_successful = pyqtSignal(dict)
    logout_successful = pyqtSignal()
    auth_required = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        
        # Load configuration
        self.load_config()
        
        # Initialize MongoDB connection
        try:
            self.mongo_client = MongoClient(self.MONGO_URI)
            self.db = self.mongo_client[self.DATABASE_NAME]
            self.users_collection = self.db[self.COLLECTION_NAME]
            print("✅ Connected to MongoDB successfully")
        except Exception as e:
            print(f"❌ MongoDB connection failed: {e}")
            self.mongo_client = None
        
        # Current user data
        self.current_user = None
        self.credentials = None
        
        # Token file for persistence
        self.token_file = "user_token.json"
        
        # Load existing credentials if available
        self.load_saved_credentials()
    
    def load_config(self):
        """Load configuration from config.py"""
        try:
            # Import from config.py
            import config
            self.CLIENT_ID = getattr(config, 'GOOGLE_CLIENT_ID', '')
            self.CLIENT_SECRET = getattr(config, 'GOOGLE_CLIENT_SECRET', '')
            self.MONGO_URI = getattr(config, 'MONGODB_URI', 'mongodb://localhost:27017/')
            self.DATABASE_NAME = getattr(config, 'DATABASE_NAME', 'ai_dashboard')
            self.COLLECTION_NAME = getattr(config, 'COLLECTION_NAME', 'users')
            self.REDIRECT_URI = getattr(config, 'REDIRECT_URI', 'http://localhost:8080/callback')
            self.SCOPES = getattr(config, 'OAUTH_SCOPES', [
                'openid',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ])
            
            print("✅ Configuration loaded from config.py")
            
        except ImportError:
            print("❌ config.py not found! Creating default configuration...")
            # Fallback to your credentials
            self.CLIENT_ID = "596153104667-81qc9pamui18d4a6sg30fbgevck5ldcr.apps.googleusercontent.com"
            self.CLIENT_SECRET = "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"
            self.MONGO_URI = "mongodb://localhost:27017/"
            self.DATABASE_NAME = "ai_dashboard"
            self.COLLECTION_NAME = "users"
            self.REDIRECT_URI = "http://localhost:8080/callback"
            self.SCOPES = [
                'openid',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ]
        
        # Validate configuration
        if not self.CLIENT_ID or not self.CLIENT_SECRET:
            print("❌ Google OAuth credentials not configured!")
        else:
            print(f"✅ Google OAuth configured for client: {self.CLIENT_ID[:20]}...")
        
        if not self.MONGO_URI:
            print("❌ MongoDB URI not configured!")
        else:
            print(f"✅ MongoDB configured: {self.MONGO_URI}")
    
    def load_saved_credentials(self):
        """Load saved credentials from file"""
        if os.path.exists(self.token_file):
            try:
                with open(self.token_file, 'r') as f:
                    token_data = json.load(f)
                
                self.credentials = Credentials(
                    token=token_data.get('token'),
                    refresh_token=token_data.get('refresh_token'),
                    token_uri=token_data.get('token_uri'),
                    client_id=token_data.get('client_id'),
                    client_secret=token_data.get('client_secret'),
                    scopes=token_data.get('scopes')
                )
                
                print("🔄 Loading saved credentials...")
                
                # Try to get user info (this will handle token refresh if needed)
                user_info = self.get_user_info_from_token()
                
                if user_info:
                    self.current_user = user_info
                    print(f"✅ Auto-logged in as: {user_info.get('name')}")
                    return True
                else:
                    print("❌ Saved credentials are invalid")
                    self.cleanup_saved_credentials()
                    return False
                        
            except Exception as e:
                print(f"⚠️ Failed to load saved credentials: {e}")
                self.cleanup_saved_credentials()
        
        return False
    
    def save_credentials(self):
        """Save credentials to file"""
        if self.credentials:
            try:
                token_data = {
                    'token': self.credentials.token,
                    'refresh_token': self.credentials.refresh_token,
                    'token_uri': self.credentials.token_uri,
                    'client_id': self.credentials.client_id,
                    'client_secret': self.credentials.client_secret,
                    'scopes': self.credentials.scopes
                }
                
                with open(self.token_file, 'w') as f:
                    json.dump(token_data, f, indent=2)
                    
                print("✅ Credentials saved successfully")
            except Exception as e:
                print(f"❌ Failed to save credentials: {e}")
    
    def cleanup_saved_credentials(self):
        """Remove saved credentials file"""
        if os.path.exists(self.token_file):
            try:
                os.remove(self.token_file)
                print("🗑️ Cleaned up saved credentials")
            except Exception as e:
                print(f"❌ Failed to cleanup credentials: {e}")
    
    def initiate_google_auth(self):
        """Start Google OAuth flow"""
        try:
            # Validate credentials first
            if not self.CLIENT_ID or not self.CLIENT_SECRET:
                raise Exception("Google OAuth credentials not configured")
            
            # Create the flow using the client secrets
            flow = google_auth_oauthlib.flow.Flow.from_client_config(
                {
                    "web": {
                        "client_id": self.CLIENT_ID,
                        "client_secret": self.CLIENT_SECRET,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [self.REDIRECT_URI]
                    }
                },
                scopes=self.SCOPES
            )
            
            flow.redirect_uri = self.REDIRECT_URI
            
            # Get the authorization URL
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent'
            )
            
            print(f"🔗 Opening browser for authentication...")
            print(f"Auth URL: {auth_url}")
            
            # Open browser for authentication
            import webbrowser
            webbrowser.open(auth_url)
            
            # Start local server to handle callback
            self.start_callback_server(flow)
            
        except Exception as e:
            print(f"❌ Authentication initiation failed: {e}")
            self.auth_required.emit()
    
    def start_callback_server(self, flow):
        """Start local server to handle OAuth callback"""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import urllib.parse
        import threading
        
        class CallbackHandler(BaseHTTPRequestHandler):
            def __init__(self, auth_manager, *args, **kwargs):
                self.auth_manager = auth_manager
                super().__init__(*args, **kwargs)
            
            def do_GET(self):
                if self.path.startswith('/callback'):
                    try:
                        # Parse the authorization response
                        query_params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                        
                        if 'code' in query_params:
                            auth_code = query_params['code'][0]
                            print(f"✅ Received authorization code: {auth_code[:20]}...")
                            
                            # Exchange authorization code for tokens
                            flow.fetch_token(code=auth_code)
                            print("✅ Token exchange successful")
                            
                            # Save credentials and get user info
                            self.auth_manager.credentials = flow.credentials
                            self.auth_manager.save_credentials()
                            
                            # Get user information
                            user_info = self.auth_manager.get_user_info_from_token()
                            
                            if user_info:
                                print(f"✅ User info retrieved: {user_info.get('name')}")
                                
                                # Save/update user in MongoDB
                                self.auth_manager.save_user_to_database(user_info)
                                self.auth_manager.current_user = user_info
                                
                                # Send success response
                                self.send_response(200)
                                self.send_header('Content-type', 'text/html')
                                self.end_headers()
                                success_html = """
                                <html>
                                <head>
                                    <title>Authentication Successful</title>
                                    <meta charset="utf-8">
                                </head>
                                <body style="font-family: 'Segoe UI', Arial, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; margin: 0;">
                                    <div style="background: rgba(255,255,255,0.1); padding: 40px; border-radius: 20px; backdrop-filter: blur(10px); max-width: 500px; margin: 0 auto;">
                                        <h1 style="font-size: 2.5em; margin-bottom: 20px;">🎉 Authentication Successful!</h1>
                                        <p style="font-size: 1.2em; margin-bottom: 30px;">Welcome to AI Dashboard!</p>
                                        <p style="font-size: 1em; opacity: 0.8;">You can now close this tab and return to the application.</p>
                                        <div style="margin-top: 30px;">
                                            <button onclick="window.close()" style="background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.3); padding: 12px 24px; border-radius: 25px; font-size: 1em; cursor: pointer;">Close Tab</button>
                                        </div>
                                    </div>
                                    <script>
                                        setTimeout(function(){ 
                                            window.close(); 
                                        }, 5000);
                                    </script>
                                </body>
                                </html>
                                """
                                self.wfile.write(success_html.encode('utf-8'))
                                
                                # Emit success signal
                                self.auth_manager.login_successful.emit(user_info)
                                
                            else:
                                raise Exception("Failed to get user information")
                        
                        elif 'error' in query_params:
                            error = query_params['error'][0]
                            error_description = query_params.get('error_description', [''])[0]
                            raise Exception(f"Authentication error: {error} - {error_description}")
                            
                    except Exception as e:
                        print(f"❌ Callback handling failed: {e}")
                        self.send_response(400)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        error_html = f"""
                        <html>
                        <head>
                            <title>Authentication Failed</title>
                            <meta charset="utf-8">
                        </head>
                        <body style="font-family: 'Segoe UI', Arial, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); color: white; margin: 0;">
                            <div style="background: rgba(255,255,255,0.1); padding: 40px; border-radius: 20px; backdrop-filter: blur(10px); max-width: 500px; margin: 0 auto;">
                                <h1 style="font-size: 2.5em; margin-bottom: 20px;">❌ Authentication Failed</h1>
                                <p style="font-size: 1.1em; margin-bottom: 20px;">Error: {str(e)}</p>
                                <p style="font-size: 1em; opacity: 0.8;">Please close this tab and try again.</p>
                                <div style="margin-top: 30px;">
                                    <button onclick="window.close()" style="background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.3); padding: 12px 24px; border-radius: 25px; font-size: 1em; cursor: pointer;">Close Tab</button>
                                </div>
                            </div>
                        </body>
                        </html>
                        """
                        self.wfile.write(error_html.encode('utf-8'))
                        
                        self.auth_manager.auth_required.emit()
                
                # Shutdown server after handling request
                threading.Thread(target=lambda: self.server.shutdown()).start()
            
            def log_message(self, format, *args):
                # Suppress default logging
                pass
        
        # Create server
        try:
            server = HTTPServer(('localhost', 8080), 
                              lambda *args, **kwargs: CallbackHandler(self, *args, **kwargs))
            
            # Store server reference for shutdown
            CallbackHandler.server = server
            
            print("🚀 Starting callback server on http://localhost:8080")
            
            # Run server in separate thread
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
        except Exception as e:
            print(f"❌ Failed to start callback server: {e}")
            print("💡 Make sure port 8080 is not in use by another application")
    
    def get_user_info_from_token(self):
        """Get user information from Google API using the access token"""
        if not self.credentials:
            print("❌ No credentials available")
            return None
        
        try:
            # Check if credentials are expired and try to refresh
            if self.credentials.expired and self.credentials.refresh_token:
                print("🔄 Token expired, attempting to refresh...")
                try:
                    self.credentials.refresh(Request())
                    self.save_credentials()  # Save refreshed credentials
                    print("✅ Token refreshed successfully")
                except Exception as refresh_error:
                    print(f"❌ Token refresh failed: {refresh_error}")
                    self.cleanup_saved_credentials()
                    return None
            
            # Make request to Google's userinfo endpoint
            headers = {'Authorization': f'Bearer {self.credentials.token}'}
            response = requests.get(
                'https://www.googleapis.com/oauth2/v2/userinfo', 
                headers=headers,
                timeout=10  # Add timeout
            )
            
            if response.status_code == 200:
                user_data = response.json()
                print(f"✅ Retrieved user data: {user_data.get('name')} ({user_data.get('email')})")
                
                # Structure the user information
                user_info = {
                    'google_id': user_data.get('id'),
                    'email': user_data.get('email'),
                    'name': user_data.get('name'),
                    'picture': user_data.get('picture'),
                    'verified_email': user_data.get('verified_email', False),
                    'last_login': datetime.now().isoformat()
                }
                
                return user_info
                
            elif response.status_code == 401:
                print(f"❌ Token invalid (401). Response: {response.text}")
                
                # Try to refresh token if we have a refresh token
                if self.credentials.refresh_token:
                    print("🔄 Attempting token refresh due to 401 error...")
                    try:
                        self.credentials.refresh(Request())
                        self.save_credentials()
                        
                        # Retry the request with new token
                        headers = {'Authorization': f'Bearer {self.credentials.token}'}
                        retry_response = requests.get(
                            'https://www.googleapis.com/oauth2/v2/userinfo', 
                            headers=headers,
                            timeout=10
                        )
                        
                        if retry_response.status_code == 200:
                            user_data = retry_response.json()
                            print(f"✅ Retrieved user data after refresh: {user_data.get('name')}")
                            
                            user_info = {
                                'google_id': user_data.get('id'),
                                'email': user_data.get('email'),
                                'name': user_data.get('name'),
                                'picture': user_data.get('picture'),
                                'verified_email': user_data.get('verified_email', False),
                                'last_login': datetime.now().isoformat()
                            }
                            
                            return user_info
                        else:
                            print(f"❌ Retry also failed: {retry_response.status_code}")
                            
                    except Exception as refresh_error:
                        print(f"❌ Token refresh failed: {refresh_error}")
                
                # Clear invalid credentials
                print("🗑️ Clearing invalid credentials")
                self.cleanup_saved_credentials()
                return None
                
            else:
                print(f"❌ Failed to get user info: {response.status_code} - {response.text}")
                return None
                    
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error getting user info: {e}")
            return None
        except Exception as e:
            print(f"❌ Error getting user info: {e}")
            return None
    
    def save_user_to_database(self, user_info):
        """Save or update user information in MongoDB"""
        if not self.mongo_client or not user_info:
            print("⚠️ MongoDB not available or no user info")
            return False
        
        try:
            # Create unique user identifier
            user_id = user_info.get('google_id')
            email = user_info.get('email')
            
            if not user_id or not email:
                print("❌ Missing required user information")
                return False
            
            # Check if user already exists
            existing_user = self.users_collection.find_one({'google_id': user_id})
            
            user_document = {
                'google_id': user_id,
                'email': email,
                'name': user_info.get('name'),
                'picture': user_info.get('picture'),
                'verified_email': user_info.get('verified_email', False),
                'last_login': datetime.now(),
                'updated_at': datetime.now()
            }
            
            if existing_user:
                # Update existing user
                result = self.users_collection.update_one(
                    {'google_id': user_id},
                    {'$set': user_document}
                )
                print(f"✅ Updated existing user: {user_info.get('name')}")
            else:
                # Create new user
                user_document['created_at'] = datetime.now()
                user_document['login_count'] = 1
                
                result = self.users_collection.insert_one(user_document)
                print(f"✅ Created new user: {user_info.get('name')}")
            
            return True
            
        except Exception as e:
            print(f"❌ Database save failed: {e}")
            return False
    
    def is_user_authenticated(self):
        """Check if user is currently authenticated"""
        if not self.current_user or not self.credentials:
            print("ℹ️ No current user or credentials")
            return False
        
        # Check if credentials are still valid by making a test request
        try:
            # If token is expired, try to refresh
            if self.credentials.expired and self.credentials.refresh_token:
                print("🔄 Refreshing expired credentials...")
                self.credentials.refresh(Request())
                self.save_credentials()
            
            # Test the token by making a lightweight API call
            headers = {'Authorization': f'Bearer {self.credentials.token}'}
            response = requests.get(
                'https://www.googleapis.com/oauth2/v1/tokeninfo',
                params={'access_token': self.credentials.token},
                timeout=5
            )
            
            if response.status_code == 200:
                token_info = response.json()
                # Check if token is for our client and has required scopes
                if token_info.get('audience') == self.CLIENT_ID:
                    return True
                else:
                    print("❌ Token audience mismatch")
            else:
                print(f"❌ Token validation failed: {response.status_code}")
                
        except Exception as e:
            print(f"⚠️ Credential validation failed: {e}")
        
        # If we get here, authentication failed
        print("🔐 Authentication invalid, requiring fresh login")
        self.logout()
        return False
    
    def get_user_info(self):
        """Get current user information"""
        return self.current_user
    
    def logout(self):
        """Logout current user"""
        try:
            # Update last logout in database
            if self.mongo_client and self.current_user:
                self.users_collection.update_one(
                    {'google_id': self.current_user.get('google_id')},
                    {'$set': {'last_logout': datetime.now()}}
                )
            
            # Clear current session
            self.current_user = None
            self.credentials = None
            
            # Remove saved credentials
            self.cleanup_saved_credentials()
            
            print("👋 User logged out successfully")
            
            # Emit logout signal
            self.logout_successful.emit()
            
        except Exception as e:
            print(f"❌ Logout error: {e}")
    
    def require_authentication(self):
        """Emit signal requiring authentication"""
        self.auth_required.emit()