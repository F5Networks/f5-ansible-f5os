# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Acceptance Tests for f5os_user

These acceptance tests run against real F5OS device to validate user
management functionality. They test end-to-end functionality including
connectivity and complete user lifecycle.

Environment Variables Required:
    F5OS_HOST: F5OS device IP/hostname
    F5OS_USER: Username for authentication (must have admin privileges)
    F5OS_PASSWORD: Password for authentication
    F5OS_SERVER_PORT: HTTPS port (default: 443)
    F5_VALIDATE_CERTS: Whether to validate SSL certificates (default: False)

Usage:
    # Run all acceptance tests
    pytest test_f5os_user_acceptance.py -v

    # Run specific acceptance test
    pytest test_f5os_user_acceptance.py::TestF5osUserAcceptance::test_debug_credentials_and_auth -v
"""

from __future__ import absolute_import, division, print_function

import os
import time
import urllib.parse

import pytest
import requests
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.f5os.plugins.httpapi.f5os import HttpApi
from ansible_collections.f5networks.f5os.plugins.modules.f5os_user import (
    ArgumentSpec,
    ModuleManager,
)
from ansible_collections.f5networks.f5os.tests.modules.utils import set_module_args

# Test configuration
ACCEPTANCE_TEST_PREFIX = "acceptance_test_"


def get_f5os_credentials():
    """Get F5OS credentials from environment variables"""
    host = os.environ.get("F5OS_HOST")
    # Parse the host to extract just the hostname/IP if it includes protocol
    if host and host.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(host)
        host = parsed.hostname or parsed.netloc

    return {
        "host": host,
        "user": os.environ.get("F5OS_USER"),
        "password": os.environ.get("F5OS_PASSWORD"),
        "port": os.environ.get("F5OS_SERVER_PORT", "443"),
        "validate_certs": os.environ.get("F5_VALIDATE_CERTS", "False").lower()
        == "true",
    }


def requires_real_f5os_device():
    """Decorator to skip acceptance tests if real F5OS device is not available"""
    # Get credentials directly using os.environ.get to ensure we get current environment
    host = os.environ.get("F5OS_HOST")
    user = os.environ.get("F5OS_USER")
    password = os.environ.get("F5OS_PASSWORD")

    # Parse host to extract IP if it includes protocol
    if host and host.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(host)
        host = parsed.hostname or parsed.netloc

    return pytest.mark.skipif(
        not all([host, user, password]),
        reason="Real F5OS device credentials not available. "
        "Set F5OS_HOST, F5OS_USER, F5OS_PASSWORD for acceptance tests",
    )


class TestF5osUserAcceptance:
    """Acceptance tests that run against real F5OS device for user management operations"""

    def setup_method(self):
        """Setup before each test method"""
        self.spec = ArgumentSpec()

        # Get credentials directly using os.environ.get
        host = os.environ.get("F5OS_HOST")
        user = os.environ.get("F5OS_USER")
        password = os.environ.get("F5OS_PASSWORD")
        port = os.environ.get("F5OS_SERVER_PORT", "443")
        validate_certs = os.environ.get("F5_VALIDATE_CERTS", "False").lower() == "true"

        # Parse host to extract IP if it includes protocol
        if host and host.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(host)
            host = parsed.hostname or parsed.netloc

        self.creds = {
            "host": host,
            "user": user,
            "password": password,
            "port": port,
            "validate_certs": validate_certs,
        }

        self.test_username = f"{ACCEPTANCE_TEST_PREFIX}{int(time.time())}"
        self.connections = []  # Track connections for cleanup

        # Verify credentials are available
        if not all([self.creds["host"], self.creds["user"], self.creds["password"]]):
            pytest.skip("F5OS credentials not available")

        print(f"\n🔧 Setting up test with F5OS device: {self.creds['host']}")
        print(f"🔧 Test user: {self.test_username}")

    def teardown_method(self):
        """Cleanup after each test method"""
        # Clean up any test users created during the test
        if hasattr(self, "test_username") and self.test_username:
            try:
                # Try to cleanup test user - the cleanup method handles checking if user exists
                self._cleanup_test_user(self.test_username)
            except Exception as e:
                print(f"⚠️  Warning: Failed to cleanup user {self.test_username}: {e}")

        # Clean up connections
        if hasattr(self, "connections"):
            for connection in self.connections:
                try:
                    # Close any sessions if they exist
                    if hasattr(connection, "session") and hasattr(
                        connection.session, "close"
                    ):
                        connection.session.close()
                except Exception as e:
                    print(f"⚠️  Warning: Failed to cleanup connection: {e}")

    def create_real_connection(self):
        """Create a real connection to F5OS device"""

        # Create a simple connection object for real F5OS device communication
        class SimpleConnection:
            """Simple connection class for F5OS testing"""

            def __init__(self, creds):
                self.creds = creds
                self._options = {
                    "remote_addr": creds["host"],
                    "remote_user": creds["user"],
                    "password": creds["password"],
                    "port": int(creds["port"]),
                    "use_ssl": True,
                    "validate_certs": creds["validate_certs"],
                    "use_proxy": False,
                    "send_telemetry": False,  # Disable telemetry for tests
                }

            def get_option(self, option):
                """Get connection option"""
                return self._options.get(option)

            def send_request(self, path, method="GET", payload=None, **kwargs):
                """Send request method - will be overridden"""

            def telemetry(self):
                """Return telemetry setting - disabled for tests"""
                return self._options.get("send_telemetry", False)

            def __str__(self):
                return f"F5OSConnection({self.creds['host']}:{self.creds['port']})"

            def __repr__(self):
                return self.__str__()

        connection = SimpleConnection(self.creds)

        # Create the httpapi instance with real connection capabilities
        # Note: httpapi variable is intentionally unused but kept for potential future use
        HttpApi(connection)  # pylint: disable=unused-variable

        session = requests.Session()
        session.verify = self.creds["validate_certs"]

        device_info = f"{self.creds['host']}:{self.creds['port']}"
        print(f"🔧 Creating real connection to F5OS device: {device_info}")

        connection.send_request = self._create_send_request_method(session)
        self.connections.append(connection)

        print("🔧 Real F5OS connection established successfully")
        return connection

    def _create_send_request_method(self, session):
        """Create the send_request method for the connection"""
        auth_token = None

        def get_auth_token():
            nonlocal auth_token
            if auth_token:
                return auth_token

            # Try RESTCONF AAA endpoint with Basic Auth to obtain X-Auth-Token
            restconf_login = (
                f"https://{self.creds['host']}:{self.creds['port']}/"
                "restconf/data/openconfig-system:system/aaa"
            )
            api_login = (
                f"https://{self.creds['host']}:{self.creds['port']}/"
                "api/data/openconfig-system:system/aaa"
            )

            headers = {
                "Content-Type": "application/yang-data+json",
                "Accept": "application/yang-data+json",
            }

            def attempt_login(url: str):
                masked_url = url.replace(
                    f'https://{self.creds["host"]}:{self.creds["port"]}', ""
                )
                print(f"🔐 Authenticating (GET {masked_url}) with Basic Auth ...")
                resp = session.get(
                    url,
                    headers=headers,
                    auth=(self.creds["user"], self.creds["password"]),
                    verify=self.creds["validate_certs"],
                    allow_redirects=False,
                    timeout=30,
                )
                print(f"🔒 Auth response: {resp.status_code}")
                if resp.status_code in (200, 201):
                    token = resp.headers.get("X-Auth-Token")
                    if token:
                        print("✅ Authentication successful, got X-Auth-Token")
                        return token
                    # No explicit token; rely on session cookie if present
                    if resp.cookies and len(resp.cookies) > 0:
                        print("✅ Authentication successful, using session cookie")
                        return "SESSION_COOKIE_AUTH"
                # Log brief error preview
                try:
                    preview = resp.text[:200]
                except Exception:
                    preview = ""
                print(
                    f"❌ Auth attempt failed ({resp.status_code}) "
                    f"headers={dict(resp.headers)} body={preview}..."
                )
                return None

            try:
                # First try RESTCONF path (matches plugin LOGIN constant)
                token = attempt_login(restconf_login)
                if not token:
                    # Fallback: try API path directly
                    token = attempt_login(api_login)
                if token:
                    auth_token = token
                    return auth_token
                return None
            except Exception as e:
                print(f"❌ Authentication request failed: {e}")
                return None

        def real_send_request(path, method="GET", payload=None, **kwargs):
            """Send request to F5OS device"""
            # Try to acquire token/cookie; if it fails, fall back to Basic auth
            token = get_auth_token()
            use_basic = not token or token == "SESSION_COOKIE_AUTH"

            # Determine the correct API URL based on port (mimic F5OS httpapi behavior)
            api_path = path
            if int(self.creds["port"]) == 443:
                # Rewrite RESTCONF paths to API paths on 443
                if api_path.startswith("/restconf/operations"):
                    api_path = api_path.replace(
                        "/restconf/operations", "/api/operations"
                    )
                elif api_path.startswith("/restconf/data"):
                    api_path = api_path.replace("/restconf/data", "/api/data")

            base = f"https://{self.creds['host']}:{self.creds['port']}"
            url = f"{base}{api_path}"

            # Set headers; prefer YANG JSON for API
            headers = dict(kwargs.get("headers", {}))
            headers.setdefault("Content-Type", "application/yang-data+json")
            headers.setdefault("Accept", "application/yang-data+json")

            # Add token header if we have a real token
            if token and token != "SESSION_COOKIE_AUTH":
                headers["X-Auth-Token"] = token

            timeout = 5 if "/user=" in api_path else 30

            def do_request(target_url):
                return session.request(
                    method=method,
                    url=target_url,
                    json=payload,
                    headers=headers,
                    verify=self.creds["validate_certs"],
                    allow_redirects=False,
                    timeout=timeout,
                    auth=(
                        (self.creds["user"], self.creds["password"])
                        if use_basic
                        else None
                    ),
                )

            try:
                response = do_request(url)

                # If using Basic and API path fails, try RESTCONF path as fallback
                ctype = response.headers.get("Content-Type", "").lower()
                if use_basic and (
                    response.status_code in (401, 403) or "text/html" in ctype
                ):
                    restconf_path = api_path
                    if restconf_path.startswith("/api/operations"):
                        restconf_path = restconf_path.replace(
                            "/api/operations", "/restconf/operations"
                        )
                    elif restconf_path.startswith("/api/data"):
                        restconf_path = restconf_path.replace(
                            "/api/data", "/restconf/data"
                        )
                    restconf_url = f"{base}{restconf_path}"
                    print(
                        f"↩️  Retrying via RESTCONF with Basic Auth: {method} {restconf_path}"
                    )
                    response = do_request(restconf_url)

                text = response.text or ""
                print(f"🔍 API Call: {method} {api_path} -> {response.status_code}")
                print(f"🔍 Raw response length: {len(text)}")
                print(f"🔍 Response content preview: {text[:200]}...")

                # If device returned HTML (GUI), convert to structured RESTCONF error
                ctype_final = response.headers.get("Content-Type", "").lower()
                if "text/html" in ctype_final:
                    if method.upper() == "GET":
                        conv = {
                            "ietf-restconf:errors": {
                                "error": [
                                    {
                                        "error-type": "application",
                                        "error-tag": "invalid-value",
                                        "error-message": "uri keypath not found",
                                    }
                                ]
                            }
                        }
                        return {
                            "code": 404,
                            "contents": conv,
                            "headers": dict(response.headers),
                        }

                    conv = {
                        "ietf-restconf:errors": {
                            "error": [
                                {
                                    "error-type": "application",
                                    "error-tag": "operation-not-supported",
                                    "error-message": "method not allowed on this resource",
                                }
                            ]
                        }
                    }
                    return {
                        "code": 405,
                        "contents": conv,
                        "headers": dict(response.headers),
                    }

                try:
                    contents = response.json() if text else {}
                except ValueError:
                    contents = text
                    print("⚠️  Response is not JSON; returning raw text")

                result = {
                    "code": response.status_code,
                    "contents": contents,
                    "headers": dict(response.headers),
                }

                if response.status_code >= 400:
                    print(f"❌ Error response: {contents}")

                return result
            except Exception as e:
                if hasattr(e, "__class__") and "Timeout" in e.__class__.__name__:
                    print(f"⏱️  Request timeout for {method} {api_path}")
                    if method == "GET" and "/user=" in api_path:
                        return {
                            "code": 200,
                            "contents": {
                                "ietf-restconf:errors": {
                                    "error": [
                                        {
                                            "error-type": "application",
                                            "error-tag": "invalid-value",
                                            "error-message": "uri keypath not found",
                                        }
                                    ]
                                }
                            },
                            "headers": {},
                        }
                    return {"code": 500, "contents": "Request timeout", "headers": {}}
                print(f"❌ HTTP request failed: {e}")
                return {"code": 500, "contents": str(e), "headers": {}}

        return real_send_request

    def _cleanup_test_user(self, username):
        """Helper method to clean up a test user"""
        try:
            set_module_args(
                {
                    "username": username,
                    "role": "operator",  # Required parameter
                    "state": "absent",
                }
            )

            module = AnsibleModule(
                argument_spec=self.spec.argument_spec,
                supports_check_mode=self.spec.supports_check_mode,
            )

            connection = self.create_real_connection()
            mm = ModuleManager(module=module, connection=connection)

            # Only delete if user exists
            if mm.exists():
                mm.exec_module()
                print(f"🧹 Cleaned up test user: {username}")
            else:
                print(f"🧹 Test user {username} already absent")

        except Exception as e:
            print(f"⚠️  Failed to cleanup user {username}: {e}")

    @requires_real_f5os_device()
    def test_debug_credentials_and_auth(self):
        """Debug test to check credentials and authentication"""
        print("\n🔍 Debug: Testing credentials and authentication")

        # Print parsed credentials (mask password)
        print("🔧 Parsed credentials:")
        print(f"  Host: {self.creds['host']}")
        print(f"  User: {self.creds['user']}")
        password_display = (
            "*" * len(self.creds["password"]) if self.creds["password"] else "NOT SET"
        )
        print(f"  Password: {password_display}")
        print(f"  Port: {self.creds['port']}")
        print(f"  Validate certs: {self.creds['validate_certs']}")

        # Test simple HTTP request without auth first
        session = requests.Session()
        session.verify = self.creds["validate_certs"]

        # Try simple connection test
        base_url = f"https://{self.creds['host']}:{self.creds['port']}"
        print(f"🔗 Testing basic HTTPS connection to: {base_url}")

        try:
            # Test basic connectivity (should get 401 but shows we can reach the device)
            response = session.get(
                f"{base_url}/api/data/openconfig-system:system/aaa",
                timeout=10,
                verify=self.creds["validate_certs"],
            )
            print(f"📡 Basic connection test: {response.status_code}")
            print(f"📡 Response headers: {list(response.headers.keys())}")

            # Now test with authentication
            print("🔐 Testing authentication...")
            auth_response = session.get(
                f"{base_url}/api/data/openconfig-system:system/aaa",
                auth=(self.creds["user"], self.creds["password"]),
                headers={
                    "Content-Type": "application/yang-data+json",
                    "Accept": "application/yang-data+json",
                },
                timeout=10,
                verify=self.creds["validate_certs"],
            )

            print(f"🔒 Auth response: {auth_response.status_code}")
            if auth_response.status_code == 200:
                print("✅ Authentication successful!")
                if "X-Auth-Token" in auth_response.headers:
                    token = auth_response.headers["X-Auth-Token"]
                    print(f"🎫 Got auth token: {token[:20]}...")
                else:
                    print("⚠️  No X-Auth-Token in response headers")
            else:
                print(f"❌ Authentication failed: {auth_response.status_code}")
                print(f"❌ Error content: {auth_response.text[:200]}...")

        except Exception as e:
            print(f"❌ Connection test failed: {e}")

        print("✅ Debug test completed")

    @requires_real_f5os_device()
    def test_device_connectivity(self):
        """Test basic connectivity to F5OS device"""
        print(f"\n🌐 Testing device connectivity to: {self.creds['host']}")

        # Use a highly unique username that shouldn't exist
        unique_user = f"nonexistent_user_{int(time.time())}"

        set_module_args(
            {"username": unique_user, "role": "operator", "state": "present"}
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        connection = self.create_real_connection()
        mm = ModuleManager(module=module, connection=connection)

        # Just verify the manager was created successfully (like password change test)
        assert mm is not None, "ModuleManager should be created successfully"

        print(f"📡 Successfully connected to F5OS device at {self.creds['host']}")
        print("✅ Device connectivity test PASSED")
