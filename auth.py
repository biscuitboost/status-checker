import requests
import base64
from datetime import datetime, timedelta
import json
import logging
from typing import Optional, Dict, Tuple
import os
from dotenv import load_dotenv
import sqlite3

# Load environment variables
load_dotenv()

def get_db_connection():
    conn = sqlite3.connect('config/url_checker.db')
    conn.row_factory = sqlite3.Row
    return conn

class GroupAuthConfig:
    def __init__(self, group_id: int, application: str, region: str, environment: str,
                 auth_url: str, username: str, password: str):
        self.group_id = group_id
        self.application = application
        self.region = region
        self.environment = environment
        self.auth_url = auth_url
        self.username = username
        self.password = password

class TokenInfo:
    def __init__(self, token: str, expiry: datetime):
        self.token = token
        self.expiry = expiry

class TokenManager:
    _instance = None
    _tokens: Dict[int, TokenInfo] = {}  # group_id -> TokenInfo
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TokenManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def _get_basic_auth(self, username: str, password: str) -> str:
        """Generate Basic Auth header for token request"""
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"
    
    def _get_group_config(self, application: str, region: str, environment: str) -> Optional[GroupAuthConfig]:
        """Get auth configuration for a group"""
        conn = get_db_connection()
        try:
            cursor = conn.execute('''
                SELECT 
                    id,
                    application,
                    region,
                    environment,
                    auth_url,
                    auth_username,
                    auth_password
                FROM group_auth_config
                WHERE application = ? AND region = ? AND environment = ?
            ''', (application, region, environment))
            row = cursor.fetchone()
            
            if row:
                return GroupAuthConfig(
                    group_id=row['id'],
                    application=row['application'],
                    region=row['region'],
                    environment=row['environment'],
                    auth_url=row['auth_url'],
                    username=row['auth_username'],
                    password=row['auth_password']
                )
            return None
        finally:
            conn.close()
    
    def _fetch_new_token(self, config: GroupAuthConfig) -> Tuple[Optional[str], Optional[datetime]]:
        """
        Fetch a new token from the auth service for a specific group
        Returns: (token, expiry_datetime)
        """
        try:
            headers = {
                'Authorization': self._get_basic_auth(config.username, config.password),
                'Content-Type': 'application/json'
            }
            
            # Example request - replace with actual auth service details
            response = requests.post(
                config.auth_url,
                headers=headers,
                json={
                    'grant_type': 'client_credentials',
                    'scope': f'monitoring:{config.application}:{config.environment}'
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                # TODO: Update these fields based on actual response format
                token = data.get('access_token')
                expires_in = data.get('expires_in', 3600)  # Default 1 hour
                expiry = datetime.now() + timedelta(seconds=expires_in)
                return token, expiry
            else:
                self.logger.error(
                    f"Failed to fetch token for {config.application}:{config.region}:{config.environment}. "
                    f"Status: {response.status_code}"
                )
                return None, None
                
        except Exception as e:
            self.logger.error(
                f"Error fetching token for {config.application}:{config.region}:{config.environment}: {str(e)}"
            )
            return None, None
    
    def get_token(self, application: str, region: str, environment: str) -> Optional[str]:
        """
        Get a valid token for a specific group, fetching a new one if necessary
        Returns: Bearer token string or None if unable to get token
        """
        config = self._get_group_config(application, region, environment)
        if not config:
            self.logger.error(
                f"No auth configuration found for {application}:{region}:{environment}"
            )
            return None
            
        now = datetime.now()
        token_info = self._tokens.get(config.group_id)
        
        # If token is missing or expired (or about to expire in 5 minutes)
        if (not token_info or 
            not token_info.expiry or 
            token_info.expiry <= now + timedelta(minutes=5)):
            
            token, expiry = self._fetch_new_token(config)
            if token and expiry:
                self._tokens[config.group_id] = TokenInfo(token, expiry)
                return token
            return None
        
        return token_info.token
    
    def get_auth_headers(self, application: str, region: str, environment: str) -> Dict[str, str]:
        """
        Get headers with bearer token for API requests for a specific group
        Returns: Dictionary of headers
        """
        token = self.get_token(application, region, environment)
        if token:
            return {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
        return {'Content-Type': 'application/json'}

# Singleton instance
token_manager = TokenManager()

def get_auth_headers(application: str, region: str, environment: str) -> Dict[str, str]:
    """Helper function to get authentication headers for a specific group"""
    return token_manager.get_auth_headers(application, region, environment)
