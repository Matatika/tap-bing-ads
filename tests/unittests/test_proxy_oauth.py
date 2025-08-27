import sys
import types
import unittest
import os

from unittest import mock

# Create a stub for the bingads module so tests do not require the real
# dependency which is not available in the test environment.
singer_stub = types.ModuleType("singer")
singer_stub.get_logger = lambda: types.SimpleNamespace(info=lambda *a, **k: None)
sys.modules.setdefault("singer", singer_stub)
sys.modules.setdefault("singer.utils", types.ModuleType("singer.utils"))
sys.modules.setdefault("singer.metadata", types.ModuleType("singer.metadata"))
metrics_stub = types.ModuleType("singer.metrics")
metrics_stub.http_request_timer = lambda *a, **k: types.SimpleNamespace(__enter__=lambda s: None, __exit__=lambda s, *args: False)
sys.modules.setdefault("singer.metrics", metrics_stub)

bingads_stub = types.ModuleType("bingads")

class OAuthWebAuthCodeGrant:
    def __init__(self, client_id, client_secret, redirect_uri, oauth_scope=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.oauth_scope = oauth_scope
        self.access_token = None
        self.expires_in = None

    def request_oauth_tokens_by_refresh_token(self, refresh_token):
        # Minimal implementation for fallback path; not used in these tests.
        self.access_token = f"token_for_{refresh_token}"

class AuthorizationData:
    def __init__(self, account_id=None, customer_id=None, developer_token=None, authentication=None):
        self.account_id = account_id
        self.customer_id = customer_id
        self.developer_token = developer_token
        self.authentication = authentication

class ServiceClient:
    def __init__(self, name, version, **kwargs):
        self.name = name
        self.version = version
        self._authorization_data = kwargs.get("authorization_data")
        self.authorization_data = self._authorization_data

bingads_stub.OAuthWebAuthCodeGrant = OAuthWebAuthCodeGrant
bingads_stub.AuthorizationData = AuthorizationData
bingads_stub.ServiceClient = ServiceClient
bingads_stub.exceptions = types.SimpleNamespace(OAuthTokenRequestException=Exception)

sys.modules.setdefault("bingads", bingads_stub)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.modules.setdefault("suds", types.ModuleType("suds"))
sys.modules.setdefault("suds.sudsobject", types.SimpleNamespace(asdict=lambda obj: {}))
requests_stub = types.ModuleType("requests")
class DummySession:
    def get(self, *a, **k):
        return types.SimpleNamespace(status_code=200, content=b"", json=lambda: {})
requests_stub.Session = DummySession
requests_stub.post = lambda *a, **k: None
requests_stub.exceptions = types.SimpleNamespace(Timeout=Exception, ConnectionError=Exception)
sys.modules.setdefault("requests", requests_stub)
sys.modules.setdefault("arrow", types.ModuleType("arrow"))
backoff_stub = types.ModuleType("backoff")
backoff_stub.on_exception = lambda *a, **k: (lambda f: f)
backoff_stub.expo = lambda *a, **k: None
backoff_stub.constant = lambda *a, **k: None
sys.modules.setdefault("backoff", backoff_stub)
import tap_bing_ads


class TestTapBingAdsWithProxyOAuthCredentials(unittest.TestCase):
    """Test tap-bing-ads using proxy refresh credentials."""

    def setUp(self):
        self.mock_config = {
            "oauth_credentials": {
                "refresh_proxy_url": "http://localhost:8080/api/tokens/oauth2-bing/token",
                "refresh_proxy_url_auth": "Bearer proxy_url_token",
                "refresh_token": "1234",
            },
            "customer_id": "1234567890",
            "developer_token": "1234",
        }
        tap_bing_ads.CONFIG = self.mock_config

    def _mock_post(self, url, headers=None, data=None, timeout=None):
        class Resp:
            status_code = 200

            def __init__(self):
                self._json = {"access_token": "refresh_token_updated", "expires_in": 3622}
                self.request = types.SimpleNamespace(headers=headers or {})

            def json(self):
                return self._json

            def raise_for_status(self):
                pass

        self.last_post_headers = headers
        self.last_post_data = data
        return Resp()

    def test_proxy_oauth_get_authentication(self):
        with mock.patch("requests.post", side_effect=self._mock_post):
            auth = tap_bing_ads.get_authentication()

        self.assertEqual(self.last_post_headers["Authorization"], "Bearer proxy_url_token")
        self.assertEqual(self.last_post_data, '{"refresh_token": "1234"}')
        self.assertIsInstance(auth, tap_bing_ads.OAuthProxyAuthGrant)
        self.assertEqual(auth.access_token, "refresh_token_updated")

    def test_proxy_oauth_create_sdk_client(self):
        with mock.patch("requests.post", side_effect=self._mock_post):
            client = tap_bing_ads.create_sdk_client("Campaign", "1")

        self.assertEqual(self.last_post_headers["Authorization"], "Bearer proxy_url_token")
        self.assertEqual(self.last_post_data, '{"refresh_token": "1234"}')
        self.assertEqual(
            client.authorization_data.authentication.access_token,
            "refresh_token_updated",
        )

