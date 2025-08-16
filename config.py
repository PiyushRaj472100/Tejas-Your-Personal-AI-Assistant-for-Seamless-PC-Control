# config.py - Configuration file for AI Dashboard
"""
Configuration settings for AI Dashboard
Your Google OAuth credentials and MongoDB settings
"""

# Google OAuth Configuration
# Note: Removed the "http://" prefix from your Client ID - it should not be there
GOOGLE_CLIENT_ID = "596153104667-81qc9pamui18d4a6sg30fbgevck5ldcr.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"

# MongoDB Configuration  
MONGODB_URI = "mongodb://localhost:27017/"  # Local MongoDB
# For MongoDB Atlas (cloud), use format like:
# MONGODB_URI = "mongodb+srv://username:password@cluster.mongodb.net/"

DATABASE_NAME = "ai_dashboard"
COLLECTION_NAME = "users"

# Application Settings
DEBUG_MODE = True
VOICE_RECOGNITION_TIMEOUT = 5  # seconds
REDIRECT_URI = "http://localhost:8080/callback"

# OAuth Scopes
OAUTH_SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]