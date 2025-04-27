from lib.settings import settings
from gql import Client
from gql.transport.aiohttp import AIOHTTPTransport

from lib.utils.graphql import create_whoami_query
import time


class GhostwriterClient:

    def __init__(self):
        pass

    def execute(self, query, variable_values=None, serialize_variables=False):
        kwargs = {}
        if variable_values:
            kwargs["variable_values"] = variable_values
        if serialize_variables:
            kwargs["serialize_variables"] = serialize_variables
        return self.client.execute(query, **kwargs)

  

    def authenticate(self, max_retries=3, delay=5):
        print("Authenticating via Webhook...")

        for attempt in range(max_retries):
            try:
                response = self.execute(create_whoami_query())
            
                if "whoami" in response and response["whoami"]:
                    print(f"Authentication Successful: {response['whoami']['username']} (Role: {response['whoami']['role']}, Expires: {response['whoami']['expires']})")
                    return response
            
                print("Authentication failed: No valid response from API, retrying...")
        
            except Exception as e:
                print(f" Webhook authentication failed (Attempt {attempt+1}/{max_retries}): {e}")
        
            # Wait before retrying
            time.sleep(delay)

        print("Webhook authentication permanently failed after multiple attempts.")
        return None



    @property
    def transport(self):
        print("api url:", self.api_url)
        if not hasattr(self, "_transport"):
            self._transport = AIOHTTPTransport(url=self.api_url, headers=self.headers,timeout=30)
        return self._transport

    @property
    def client(self):
        if not hasattr(self, "_client"):
            self._client = Client(
                transport=self.transport, fetch_schema_from_transport=True,execute_timeout=30
            )
        return self._client

    @property
    def api_url(self):
        return settings.ghostwriter.api_url

    @property
    def bearer_token(self):
        return f"Bearer {settings.ghostwriter.api_token}"

    @property
    def headers(self):
        return {"Authorization": self.bearer_token}
