# -*- coding: utf-8 -*-
"""
OME Client module for handling authentication and REST API interactions with
Dell OpenManage Enterprise. Contains the main OME client class.
"""

# __version__ = "1.10.24" # From user's uploaded ome_client.py
__version__ = "1.11.1" # Added/updated methods for comprehensive configuration management.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history from v1.10.24) ...
# 2025-05-14 | 1.11.0  | Gemini     | Added conceptual configure_ad_provider, test_ad_provider_connection, etc.
# 2025-05-14 | 1.11.1  | Gemini     | Implemented new client methods based on user's API details.
#            |         |            | Ensured robust error handling and logging.
#            |         |            | Integrated existing AD import methods for consistency.

import requests
import logging
import json
# import socket # Not directly used in the refined methods here, but keep if other parts of your client use it.
from typing import Dict, List, Optional, Tuple, Any, Union
import urllib.parse

# Assumes constants.py is in the same directory or Python path
import constants

class AuthenticationError(Exception): pass
class OmeApiError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[Union[Dict, List, str]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body
        # Use a local logger instance for OmeApiError to avoid potential recursion if main logger fails
        error_logger = logging.getLogger(__name__ + ".OmeApiError") # Unique name for this logger
        error_logger.error(f"OME API Error (Status: {status_code if status_code is not None else 'N/A'}): {message}")
        if response_body:
            # Ensure response_body is converted to string before slicing for safety
            response_body_str = str(response_body)
            error_logger.debug(f"Error Body (first 500 chars): {response_body_str[:500]}")


class OmeClient:
    def __init__(self, url: str, username: str, password: str, logger_instance: Optional[logging.Logger] = None):
        # If a logger_instance is passed (e.g., from the main script), use it.
        # Otherwise, get a logger specific to this module.
        self.logger = logger_instance if logger_instance else logging.getLogger(__name__)
        
        if not url.startswith('http'):
            self.url = 'https://' + url
            self.logger.warning(f"OME URL '{url}' did not start with http/https, assuming HTTPS: '{self.url}'.")
        else:
            self.url = url
        self.url = self.url.rstrip('/')

        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False # For lab environments; set to True or path to CA bundle in production
        if not self.session.verify:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
            self.logger.warning("SSL certificate verification is disabled for OME requests. This is NOT recommended for production environments.")
        self._auth_token: Optional[str] = None
        self.session.headers.update({'Content-Type': 'application/json', 'Accept': 'application/json'})

    def authenticate(self):
        """Authenticates with OME and stores the session token."""
        auth_endpoint = constants.API_ENDPOINTS.get('auth')
        if not auth_endpoint:
            self.logger.critical("Authentication endpoint 'auth' is not defined in constants.API_ENDPOINTS.")
            raise ValueError("Authentication endpoint 'auth' missing in constants.")
        
        auth_url = f"{self.url}{auth_endpoint}"
        payload = {'UserName': self.username, 'Password': self.password}
        
        self.logger.info(f"Attempting to authenticate user '{self.username}' with OME at {self.url}...")
        try:
            response = self.session.post(auth_url, data=json.dumps(payload), verify=self.session.verify, timeout=30)
            
            if response.status_code in [200, 201]:
                self._auth_token = response.headers.get('X-Auth-Token')
                if not self._auth_token:
                    self.logger.error("Authentication successful but no X-Auth-Token found in response headers.")
                    raise AuthenticationError("Authentication succeeded but X-Auth-Token was not returned.")
                self.session.headers.update({'X-Auth-Token': self._auth_token})
                self.logger.info(f"Successfully authenticated with OME. Status: {response.status_code}.")
            elif response.status_code == 401:
                self.logger.error("Authentication failed: Invalid credentials (401).")
                raise AuthenticationError("Invalid OME credentials provided.")
            else:
                self.logger.error(f"Authentication failed. Status: {response.status_code}. Response: {response.text[:200]}")
                raise AuthenticationError(f"OME authentication failed with status code {response.status_code}.")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network/connection error during OME authentication: {e}", exc_info=True)
            raise AuthenticationError(f"Connection error during authentication: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during OME authentication: {e}", exc_info=True)
            raise AuthenticationError(f"Unexpected error during authentication: {e}")

    def logout(self):
        """Logs out from the OME session."""
        if not self._auth_token:
            self.logger.info("Not authenticated or already logged out. Skipping logout.")
            return
        
        # OME doesn't have a traditional "logout" endpoint.
        # Clearing the token locally is sufficient.
        self.logger.info(f"Logging out user '{self.username}' from OME (clearing local session token).")
        self._auth_token = None
        if 'X-Auth-Token' in self.session.headers:
            del self.session.headers['X-Auth-Token']
        self.logger.info("Local session token cleared.")

    def _send_api_request(self, method: str, endpoint_path: str,
                          json_data: Optional[Union[Dict, List]] = None,
                          params: Optional[Dict] = None,
                          expected_status_codes: Optional[List[int]] = None,
                          timeout: int = 60) -> Optional[Union[Dict, List, str]]:
        """Internal helper to send API requests and handle responses."""
        if not self._auth_token and not endpoint_path.endswith(constants.API_ENDPOINTS.get('auth','/api/SessionService/Sessions')):
            self.logger.error("Attempted API request without authentication.")
            raise AuthenticationError("Not authenticated. Call authenticate() first.")

        if not endpoint_path.startswith('/'):
            self.logger.warning(f"Endpoint path '{endpoint_path}' lacks leading '/'. Prepending.")
            endpoint_path = '/' + endpoint_path
        
        request_url = f"{self.url}{endpoint_path}"
        
        self.logger.debug(f"Sending API Request: {method.upper()} {request_url}")
        if params: self.logger.debug(f"  Params: {params}")
        if json_data: self.logger.debug(f"  JSON Body (first 500 chars): {json.dumps(json_data, indent=2)[:500]}...")

        try:
            response = self.session.request(
                method, request_url,
                json=json_data if method.upper() not in ['GET', 'DELETE'] else None,
                params=params, verify=self.session.verify, timeout=timeout
            )
            self.logger.debug(f"API Response Status: {response.status_code} for {method.upper()} {request_url}")

            success_codes = expected_status_codes
            if success_codes is None: # Define default success codes if not provided
                success_codes = [200]
                if method.upper() == 'POST': success_codes.extend([201, 202, 204])
                elif method.upper() in ['PUT', 'PATCH', 'DELETE']: success_codes.extend([202, 204])
            
            if response.status_code in success_codes:
                if response.status_code == 204 or not response.content: return None
                try: return response.json()
                except json.JSONDecodeError:
                    self.logger.debug("Response not JSON, returning raw text.")
                    return response.text
            else:
                err_msg = f"API call to {endpoint_path} returned unexpected status {response.status_code}."
                resp_body_for_err = ""
                try: resp_body_for_err = response.json()
                except json.JSONDecodeError: resp_body_for_err = response.text
                raise OmeApiError(err_msg, response.status_code, resp_body_for_err)

        except requests.exceptions.Timeout:
            self.logger.error(f"Request to {method.upper()} {request_url} timed out after {timeout}s.", exc_info=True)
            raise OmeApiError(f"Request timed out: {method.upper()} {request_url}", status_code=None)
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network/connection error for {method.upper()} {request_url}: {e}", exc_info=True)
            raise OmeApiError(f"Connection error: {e}", response_body=str(e))
        # OmeApiError is re-raised by default if it's already that type
        except Exception as e:
            self.logger.error(f"Unexpected error during API request to {method.upper()} {request_url}: {e}", exc_info=True)
            raise OmeApiError(f"Unexpected API request error: {e}", response_body=str(e))

    # --- AD Provider Configuration ---
    def configure_ad_provider(self, ad_config_payload: Dict) -> Optional[int]:
        """Configures (creates/updates) an AD provider."""
        # Endpoint: /api/AccountService/ExternalAccountProvider/ADAccountProvider (POST or PUT)
        # Assuming POST creates. If update is needed, logic to GET then PUT would be required.
        endpoint = constants.API_ENDPOINTS.get('ad_provider_config', "/api/AccountService/ExternalAccountProvider/ADAccountProvider")
        provider_name = ad_config_payload.get("Name", "Unknown AD Provider")
        self.logger.info(f"Configuring AD Provider '{provider_name}'...")
        try:
            # OME might return 201 with the created object including ID.
            response = self._send_api_request('POST', endpoint, json_data=ad_config_payload, expected_status_codes=[200, 201])
            if response and isinstance(response, dict) and response.get('Id') is not None:
                provider_id = int(response['Id'])
                self.logger.info(f"AD Provider '{provider_name}' configured successfully. ID: {provider_id}")
                return provider_id
            self.logger.error(f"AD Provider '{provider_name}' configuration response missing ID. Response: {response}")
            return None
        except OmeApiError as e:
            self.logger.error(f"API error configuring AD Provider '{provider_name}': {e.message}")
            return None
        except (ValueError, TypeError) as e:
            self.logger.error(f"Error parsing Provider ID from response for '{provider_name}': {e}")
            return None

    def test_ad_provider_connection(self, test_payload: Dict) -> bool:
        """Tests AD connection. Payload should include provider ID and test credentials."""
        # Endpoint: /api/AccountService/ExternalAccountProvider/Actions/ExternalAccountProvider.TestADConnection
        endpoint = constants.API_ENDPOINTS.get('ad_provider_test_connection', "/api/AccountService/ExternalAccountProvider/Actions/ExternalAccountProvider.TestADConnection")
        provider_id_from_payload = test_payload.get("Id", "Unknown")
        self.logger.info(f"Testing AD connection for Provider ID: {provider_id_from_payload}...")
        try:
            # Successful test might return 200/204.
            self._send_api_request('POST', endpoint, json_data=test_payload, expected_status_codes=[200, 204])
            self.logger.info(f"AD connection test for Provider ID {provider_id_from_payload} successful.")
            return True
        except OmeApiError as e:
            self.logger.error(f"AD connection test for Provider ID {provider_id_from_payload} failed: {e.message}")
            return False

    # --- NTP Configuration ---
    def set_ntp_configuration(self, ntp_payload: Dict) -> bool:
        """Configures NTP settings."""
        # Endpoint: /api/ApplicationService/Network/TimeConfiguration (PUT)
        endpoint = constants.API_ENDPOINTS.get('ntp_config', "/api/ApplicationService/Network/TimeConfiguration")
        self.logger.info(f"Setting NTP configuration: {ntp_payload}")
        try:
            # API usually expects PUT for updating existing config, or POST if it's an action.
            # User's payload example was a list for GET, but PUT usually takes a single object.
            # Assuming ntp_payload is the single object for PUT.
            self._send_api_request('PUT', endpoint, json_data=ntp_payload, expected_status_codes=[200, 204])
            self.logger.info("NTP configuration updated successfully.")
            return True
        except OmeApiError as e:
            self.logger.error(f"API error setting NTP configuration: {e.message}")
            return False

    # --- DNS Configuration ---
    def get_network_adapter_configurations(self) -> Optional[List[Dict]]:
        """Gets all network adapter configurations."""
        endpoint = constants.API_ENDPOINTS.get('get_adapter_configs', "/api/ApplicationService/Network/AdapterConfigurations")
        self.logger.info("Fetching network adapter configurations...")
        try:
            response = self._send_api_request('GET', endpoint)
            if isinstance(response, dict) and response.get('@odata.context') and isinstance(response.get('value'), list):
                return response['value']
            elif isinstance(response, list): # Non-OData direct list
                return response
            self.logger.warning(f"Unexpected response format for adapter configurations: {response}")
            return None
        except OmeApiError as e:
            self.logger.error(f"API error fetching adapter configurations: {e.message}")
            return None

    def configure_network_adapter(self, adapter_config_payload: Dict) -> Tuple[bool, Optional[str]]:
        """Configures a specific network adapter. Returns (initiated, job_id)."""
        # Endpoint: /api/ApplicationService/Actions/Network.ConfigureNetworkAdapter (POST)
        endpoint = constants.API_ENDPOINTS.get('configure_network_adapter_action', "/api/ApplicationService/Actions/Network.ConfigureNetworkAdapter")
        if_name = adapter_config_payload.get("InterfaceName", "Unknown Interface")
        self.logger.info(f"Configuring network adapter '{if_name}'...")
        try:
            response = self._send_api_request('POST', endpoint, json_data=adapter_config_payload, expected_status_codes=[200, 202]) # 202 if job based
            if response and isinstance(response, dict) and response.get('Id') is not None: # Job ID
                job_id = str(response['Id'])
                self.logger.info(f"Network adapter configuration job for '{if_name}' submitted. Job ID: {job_id}")
                return True, job_id
            # If API returns 200 OK without job ID for synchronous success (less likely for network changes)
            elif response is None or isinstance(response, dict): # Check if 200 OK with no job ID means sync success
                 self.logger.info(f"Network adapter '{if_name}' configuration request accepted (synchronous or no job ID returned).")
                 return True, None # No job ID to monitor
            self.logger.error(f"Network adapter configuration for '{if_name}' response missing Job ID. Response: {response}")
            return False, None
        except OmeApiError as e:
            self.logger.error(f"API error configuring network adapter '{if_name}': {e.message}")
            return False, None

    def get_job_details(self, job_id: Union[str, int]) -> Optional[Dict]:
        """Retrieves details of a specific job."""
        # Endpoint: /api/JobService/Jobs/{job_id}
        endpoint = constants.API_ENDPOINTS.get('get_job_by_id_simple', f"/api/JobService/Jobs/{job_id}").format(job_id=job_id)
        self.logger.debug(f"Fetching details for Job ID: {job_id}...")
        try:
            response = self._send_api_request('GET', endpoint)
            if isinstance(response, dict):
                return response
            self.logger.warning(f"Unexpected response format for job details {job_id}: {response}")
            return None
        except OmeApiError as e:
            if e.status_code == 404: self.logger.warning(f"Job ID {job_id} not found.")
            else: self.logger.error(f"API error fetching job {job_id}: {e.message}")
            return None

    # --- Plugin Configuration ---
    def update_console_plugins(self, plugins_action_payload: Dict) -> bool:
        """Performs actions on console plugins."""
        # Endpoint: /api/PluginService/Actions/PluginService.UpdateConsolePlugins (POST)
        # Payload: {"Plugins": [{"Id": "GUID", "Version": "1.0.0", "Action": "Install"}, ...]}
        endpoint = constants.API_ENDPOINTS.get('update_plugins_action', "/api/PluginService/Actions/PluginService.UpdateConsolePlugins")
        self.logger.info(f"Updating console plugins with payload: {json.dumps(plugins_action_payload, indent=2)[:200]}...")
        try:
            # This action might be synchronous or asynchronous (job-based).
            # Assuming 200/202/204 for success of submission.
            self._send_api_request('POST', endpoint, json_data=plugins_action_payload, expected_status_codes=[200, 202, 204])
            self.logger.info("Plugin update request submitted successfully.")
            # If job-based, response might contain Job ID. For now, assuming success on accepted request.
            return True
        except OmeApiError as e:
            self.logger.error(f"API error updating console plugins: {e.message}")
            return False

    # --- CSR Generation ---
    def generate_csr(self, csr_payload: Dict) -> Optional[str]:
        """Generates a CSR."""
        # Endpoint: /api/ApplicationService/Actions/ApplicationService.GenerateCSR (POST)
        # Payload: {"DistinguishedName":"localhost", "DepartmentName":"...", ...}
        endpoint = constants.API_ENDPOINTS.get('generate_csr_action', "/api/ApplicationService/Actions/ApplicationService.GenerateCSR")
        self.logger.info(f"Generating CSR with payload: {csr_payload}")
        try:
            # API expected to return 200 OK with {"CertificateSigningRequest": "CSR_TEXT"}
            response = self._send_api_request('POST', endpoint, json_data=csr_payload, expected_status_codes=[200])
            if isinstance(response, dict) and isinstance(response.get("CertificateSigningRequest"), str):
                csr_text = response["CertificateSigningRequest"]
                self.logger.info("CSR generated successfully.")
                return csr_text
            self.logger.error(f"CSR generation response missing 'CertificateSigningRequest' string. Response: {response}")
            return None
        except OmeApiError as e:
            self.logger.error(f"API error generating CSR: {e.message}")
            return None

    # --- Existing AD Import and Group Methods (ensure consistency) ---
    # (Copied from user's uploaded ome_client.py and adapted to use self.logger and _send_api_request)

    def get_group_by_name(self, group_name: str) -> Optional[Dict]:
        endpoint = constants.API_ENDPOINTS.get('groups')
        if not endpoint: self.logger.critical("Endpoint 'groups' missing."); raise KeyError("Endpoint 'groups' missing.")
        self.logger.debug(f"Searching for group named '{group_name}'...")
        escaped_name = group_name.replace("'", "''") # Basic OData escaping for strings
        filter_str = f"Name eq '{escaped_name}'"
        try:
            response_data = self._send_api_request('GET', endpoint, params={'$filter': filter_str, '$top': '1'})
            if response_data and isinstance(response_data, dict) and 'value' in response_data and response_data['value']:
                group_data = response_data['value'][0]
                if 'Id' in group_data and group_data['Id'] is not None: group_data['Id'] = str(group_data['Id'])
                self.logger.debug(f"Found group '{group_name}' (ID: {group_data.get('Id')}).")
                return group_data
            self.logger.debug(f"Group '{group_name}' not found.")
            return None
        except OmeApiError as e:
            self.logger.error(f"API error getting group by name '{group_name}': {e.message}")
            return None
        except Exception as e: # Catch any other unexpected error
            self.logger.error(f"Unexpected error in get_group_by_name for '{group_name}': {e}", exc_info=True)
            return None

    def create_static_group(self, group_name: str, description: Optional[str] = None, parent_id: Optional[int] = None) -> Optional[str]:
        endpoint_key = 'create_group' # From constants.py
        endpoint = constants.API_ENDPOINTS.get(endpoint_key)
        if not endpoint: self.logger.critical(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        
        self.logger.info(f"Attempting to create static group '{group_name}'" + (f" under Parent ID: {parent_id}" if parent_id is not None else " (default parent)."))
        group_model_payload: Dict[str, Any] = {
            'Name': group_name,
            'Description': description if description is not None else group_name,
            'MembershipTypeId': constants.STATIC_GROUP_MEMBERSHIP_TYPE_ID, # Should be defined in constants
        }
        if parent_id is not None:
            group_model_payload['ParentId'] = parent_id
        
        final_payload = {"GroupModel": group_model_payload}
        self.logger.debug(f"Payload for creating group ({endpoint}): {final_payload}")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=final_payload, expected_status_codes=[200, 201])
            if response_data:
                 new_id_raw = response_data.get('GroupId', response_data.get('Id')) if isinstance(response_data, dict) else None
                 if new_id_raw is None and isinstance(response_data, (str,int)): new_id_raw = response_data # If API returns ID directly

                 if new_id_raw is not None and str(new_id_raw).strip():
                     new_id_str = str(new_id_raw).strip()
                     self.logger.info(f"Static group '{group_name}' created successfully. New Group ID: {new_id_str}")
                     return new_id_str
            self.logger.error(f"Group creation '{group_name}' failed or no ID returned. Response: {response_data}")
            return None
        except OmeApiError as e:
            self.logger.error(f"API error creating group '{group_name}': {e.message}")
            raise # Re-raise to be handled by caller
        except Exception as e:
            self.logger.error(f"Unexpected error creating group '{group_name}': {e}", exc_info=True)
            raise

    def get_ad_provider_id_by_name(self, ad_provider_name: str) -> Optional[int]:
        # Copied from user's ome_client.py, adapted for self.logger and _send_api_request
        endpoint_key = 'external_account_providers'
        endpoint = constants.API_ENDPOINTS.get(endpoint_key)
        if not endpoint: self.logger.critical(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        self.logger.debug(f"Finding AD Provider ID for name: '{ad_provider_name}' using {endpoint}...")
        try:
            response_data = self._send_api_request('GET', endpoint)
            if response_data and isinstance(response_data, dict) and 'value' in response_data and isinstance(response_data['value'], list):
                for provider in response_data['value']:
                    # Ensure it's an AD provider, OME might support other types via this endpoint
                    if provider.get('Name') == ad_provider_name and provider.get("ProviderType") == "ActiveDirectory": # Example check
                        pid_raw = provider.get('Id')
                        if pid_raw is not None:
                            try: return int(pid_raw)
                            except (ValueError, TypeError): self.logger.error(f"AD Provider ID '{pid_raw}' not valid int for '{ad_provider_name}'."); return None
                        else: self.logger.warning(f"AD Provider '{ad_provider_name}' found but missing ID."); return None
                self.logger.warning(f"AD Provider '{ad_provider_name}' not found or not of type ActiveDirectory.")
            else: self.logger.warning(f"Failed to retrieve AD Providers or unexpected response: {response_data}")
        except Exception as e: self.logger.error(f"Error retrieving AD provider ID for '{ad_provider_name}': {e}", exc_info=True)
        return None

    def search_ad_group_in_ome_by_name(self, ad_provider_id: int, ad_group_name: str, ad_username: str, ad_password: str) -> Optional[Dict]:
        # Copied from user's ome_client.py, adapted
        endpoint_key = 'search_ad_groups_in_ome'
        endpoint = constants.API_ENDPOINTS.get(endpoint_key)
        if not endpoint: self.logger.critical(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        self.logger.debug(f"Searching AD group '{ad_group_name}' via OME Provider ID {ad_provider_id} using AD creds '{ad_username}'...")
        payload = {
            "DirectoryServiceId": ad_provider_id, "CommonName": ad_group_name,
            "Type": constants.AD_SEARCH_TYPE, "UserName": ad_username, "Password": ad_password
        }
        self.logger.debug(f"Payload for AD Group Search Action ({endpoint}): {payload}")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=payload)
            found_groups: List[Dict] = []
            if response_data and isinstance(response_data, dict) and 'value' in response_data and isinstance(response_data['value'], list): found_groups = response_data['value']
            elif response_data and isinstance(response_data, list): found_groups = response_data

            if found_groups:
                for group_info in found_groups: # Iterate to find an exact match or one with GUID
                    if (group_info.get('Name') == ad_group_name or group_info.get('CommonName') == ad_group_name) and group_info.get('ObjectGuid'):
                        self.logger.info(f"Found AD group '{ad_group_name}' (GUID '{group_info.get('ObjectGuid')}') via OME search."); return group_info
                # If no exact name match with GUID, check if any result has GUID
                for group_info in found_groups:
                    if group_info.get('ObjectGuid'):
                        self.logger.warning(f"Exact name match for '{ad_group_name}' not found, using first available match with GUID: Name='{group_info.get('Name')}', GUID='{group_info.get('ObjectGuid')}'")
                        return group_info
                self.logger.error(f"AD group(s) found for '{ad_group_name}' but none had a usable 'ObjectGuid'."); return None
            else: self.logger.warning(f"AD group '{ad_group_name}' not found via OME search (Provider ID {ad_provider_id})."); return None
        except Exception as e: self.logger.error(f"Error searching AD group '{ad_group_name}' via OME: {e}", exc_info=True); return None

    def get_role_id_by_name(self, role_name: str) -> Optional[str]:
        # Copied from user's ome_client.py, adapted
        endpoint_key = 'roles'
        endpoint = constants.API_ENDPOINTS.get(endpoint_key)
        if not endpoint: self.logger.critical(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        self.logger.debug(f"Fetching all roles from {endpoint} to find '{role_name}'...")
        try:
            response_data = self._send_api_request('GET', endpoint)
            all_roles: List[Dict] = []
            if response_data and isinstance(response_data, dict) and 'value' in response_data and isinstance(response_data['value'], list): all_roles = response_data['value']
            elif response_data and isinstance(response_data, list): all_roles = response_data
            for role in all_roles:
                if role.get('Name') == role_name:
                    role_id_raw = role.get('Id')
                    if role_id_raw is not None: return str(role_id_raw)
            self.logger.warning(f"OME Role '{role_name}' not found after checking all {len(all_roles)} roles.")
        except Exception as e: self.logger.error(f"Error fetching roles to find '{role_name}': {e}", exc_info=True)
        return None

    def import_ad_group(self, ad_provider_id: int, ad_group_name: str, ad_object_guid: str, role_id: str) -> Optional[str]:
        # Copied from user's ome_client.py, adapted
        endpoint_key = 'import_ad_group'
        endpoint = constants.API_ENDPOINTS.get(endpoint_key)
        if not endpoint: self.logger.critical(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        self.logger.info(f"Importing AD group '{ad_group_name}' (ObjectGuid: {ad_object_guid}, Provider {ad_provider_id}, Role {role_id}) as OME Account...")
        group_payload_dict = {
            "UserTypeId": 2, "DirectoryServiceId": ad_provider_id, "Description": ad_group_name,
            "Name": ad_group_name, "Password": "", "UserName": ad_group_name,
            "RoleId": role_id, "Locked": False, "Enabled": True, "ObjectGuid": ad_object_guid
        }
        final_payload = [group_payload_dict]
        self.logger.debug(f"Payload for AD Group Import as Account (action: {endpoint}): {final_payload}")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=final_payload, expected_status_codes=[200,201]) # Import might return 200 or 201
            if response_data:
                 new_id_raw = None
                 if isinstance(response_data, list) and response_data:
                     first_result = response_data[0]
                     if isinstance(first_result, dict): new_id_raw = first_result.get('Id')
                 elif isinstance(response_data, dict): new_id_raw = response_data.get('Id')
                 
                 if new_id_raw is not None and str(new_id_raw).strip(): return str(new_id_raw).strip()
            self.logger.error(f"AD group import for '{ad_group_name}' failed or no OME Account ID returned. Response: {response_data}"); return None
        except OmeApiError as e:
            self.logger.error(f"API error importing AD group '{ad_group_name}': {e.message}")
            raise # Re-raise
        except Exception as e:
            self.logger.error(f"Unexpected error importing AD group '{ad_group_name}': {e}", exc_info=True)
            raise

    def get_imported_ad_account_by_username(self, ad_group_as_username: str) -> Optional[Dict]:
        # Copied from user's ome_client.py, adapted
        endpoint_key = 'accounts'
        endpoint = constants.API_ENDPOINTS.get(endpoint_key)
        if not endpoint: self.logger.critical(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        self.logger.debug(f"Searching OME Accounts for UserName '{ad_group_as_username}'...")
        escaped_username = ad_group_as_username.replace("'", "''")
        filter_str = f"UserName eq '{escaped_username}' and UserTypeId eq 2" # UserTypeId 2 for Directory Users/Groups
        params = {'$filter': filter_str, '$top': '1'}
        try:
            response_data = self._send_api_request('GET', endpoint, params=params)
            if response_data and isinstance(response_data, dict) and 'value' in response_data and isinstance(response_data['value'], list):
                accounts_found = response_data['value']
                if accounts_found:
                    account = accounts_found[0]
                    if 'Id' in account and account['Id'] is not None: account['Id'] = str(account['Id'])
                    self.logger.info(f"Found existing OME Account for UserName '{ad_group_as_username}' (ID: {account.get('Id')}).")
                    return account
            self.logger.debug(f"No OME Account found with UserName '{ad_group_as_username}' and UserTypeId 2.")
        except Exception as e: self.logger.error(f"Error retrieving OME account by UserName '{ad_group_as_username}': {e}", exc_info=True)
        return None

    def add_scope_to_ad_group(self, ome_account_id: str, static_group_ids: List[str]): # Signature from user's file
        # Copied from user's ome_client.py, adapted
        endpoint_key = 'add_scope_to_ad_group'
        endpoint = constants.API_ENDPOINTS.get(endpoint_key)
        if not endpoint: self.logger.critical(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        
        if not static_group_ids:
            self.logger.info(f"No static group IDs provided to set scope for OME Account ID '{ome_account_id}'. Assuming intent to clear scopes if API supports it, or do nothing.")
            # OME's SetScope with empty "Groups" list usually clears scopes.
        else:
            self.logger.info(f"Setting scope with static group IDs {static_group_ids} for OME Account ID '{ome_account_id}'...")
        
        try:
            payload = {
                'UserId': int(ome_account_id),
                'Groups': [int(gid) for gid in static_group_ids]
            }
        except ValueError:
            self.logger.error(f"Invalid AccountID ('{ome_account_id}') or GroupID in list for SetScope. IDs must be integers.")
            raise ValueError("Invalid ID format for SetScope action.")

        self.logger.debug(f"Payload for SetScope action ({endpoint}): {payload}")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=payload, expected_status_codes=[200, 202, 204])
            if response_data is None: self.logger.info(f"SetScope request for Account ID {ome_account_id} completed (204 No Content).")
            elif isinstance(response_data, dict) and 'Id' in response_data: self.logger.info(f"SetScope job created for Account ID {ome_account_id}. Job ID: {response_data['Id']}")
            else: self.logger.info(f"SetScope request sent for Account ID {ome_account_id}. Response: {str(response_data)[:200]}")
        except OmeApiError as e:
            self.logger.error(f"API error setting scope for OME Account ID {ome_account_id}: {e.message}")
            raise # Re-raise to be handled by caller
        except Exception as e:
            self.logger.error(f"Unexpected error setting scope for OME Account ID {ome_account_id}: {e}", exc_info=True)
            raise
    def get_network_adapter_configurations(self) -> Optional[List[Dict]]:
        """Gets all network adapter configurations."""
        # Endpoint: GET /api/ApplicationService/Network/AdapterConfigurations
        endpoint = constants.API_ENDPOINTS.get('get_adapter_configs', "/api/ApplicationService/Network/AdapterConfigurations")
        self.logger.info("Fetching network adapter configurations...")
        try:
            response = self._send_api_request('GET', endpoint)
            if isinstance(response, dict) and response.get('@odata.context') and isinstance(response.get('value'), list):
                return response['value']
            elif isinstance(response, list): # Non-OData direct list
                return response
            self.logger.warning(f"Unexpected response format for adapter configurations: {response}")
            return None
        except OmeApiError as e: # Assuming OmeApiError is defined
            self.logger.error(f"API error fetching adapter configurations: {e.message}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error fetching adapter configurations: {e}", exc_info=True)
            return None

    def configure_network_adapter(self, adapter_config_payload: Dict) -> Tuple[bool, Optional[str]]:
        """Configures a specific network adapter. Returns (initiated, job_id)."""
        # Endpoint: /api/ApplicationService/Actions/Network.ConfigureNetworkAdapter (POST)
        endpoint = constants.API_ENDPOINTS.get('configure_network_adapter_action', "/api/ApplicationService/Actions/Network.ConfigureNetworkAdapter")
        if_name = adapter_config_payload.get("InterfaceName", "Unknown Interface")
        self.logger.info(f"Configuring network adapter '{if_name}'...")
        try:
            response = self._send_api_request('POST', endpoint, json_data=adapter_config_payload, expected_status_codes=[200, 202]) # 202 if job based
            if response and isinstance(response, dict) and response.get('Id') is not None: # Job ID
                job_id = str(response['Id'])
                self.logger.info(f"Network adapter configuration job for '{if_name}' submitted. Job ID: {job_id}")
                return True, job_id
            elif response is None or isinstance(response, dict): 
                 self.logger.info(f"Network adapter '{if_name}' configuration request accepted (synchronous or no job ID returned).")
                 return True, None 
            self.logger.error(f"Network adapter configuration for '{if_name}' response missing Job ID. Response: {response}")
            return False, None
        except OmeApiError as e:
            self.logger.error(f"API error configuring network adapter '{if_name}': {e.message}")
            return False, None
        except Exception as e:
            self.logger.error(f"Unexpected error configuring network adapter '{if_name}': {e}", exc_info=True)
            return False, None

def configure_network_adapter_dns(self, preferred_dns: str, alternate_dns: Optional[str]) -> Tuple[bool, Optional[str]]:
        """
        Helper method to find the primary network adapter, update its DNS settings,
        and submit the configuration change.
        Returns: (True if job submission was successful, Job ID if returned, else None)
        """
        self.logger.info(f"Attempting to configure DNS on primary adapter. Preferred: {preferred_dns}, Alternate: {alternate_dns or 'None'}")
        adapters = self.get_network_adapter_configurations()
        if not adapters:
            self.logger.error("Could not retrieve network adapter configurations to set DNS.")
            return False, None

        primary_adapter_config = None
        for adapter in adapters:
            if adapter.get("PrimaryInterface") is True: # OME uses "PrimaryInterface": true
                primary_adapter_config = adapter
                break
        
        if not primary_adapter_config:
            self.logger.error("No primary network adapter found to configure DNS.")
            return False, None

        interface_name_for_log = primary_adapter_config.get('InterfaceName', 'UnknownPrimaryInterface')
        self.logger.info(f"Found primary network adapter: {interface_name_for_log}")

        # Prepare payload for Network.ConfigureNetworkAdapter
        # Start with the existing primary adapter config and modify it.
        # Remove @odata.* fields before POSTing back.
        payload_for_post = {key: value for key, value in primary_adapter_config.items() if not key.startswith('@odata')}

        # Ensure Ipv4Configuration exists
        if 'Ipv4Configuration' not in payload_for_post or not isinstance(payload_for_post.get('Ipv4Configuration'), dict):
            payload_for_post['Ipv4Configuration'] = {} # Initialize if missing or not a dict
        
        # Modify IPv4 DNS settings
        payload_for_post['Ipv4Configuration']['UseDHCPForDNSServerNames'] = False
        payload_for_post['Ipv4Configuration']['StaticPreferredDNSServer'] = preferred_dns
        payload_for_post['Ipv4Configuration']['StaticAlternateDNSServer'] = alternate_dns if alternate_dns else ""

        # Ensure other required fields for Ipv4Configuration are present if API needs them,
        # even if just carrying over existing values or defaults.
        # Example: If EnableDHCP must be explicitly sent.
        if 'EnableDHCP' not in payload_for_post['Ipv4Configuration']:
             # If DHCP was true, and we are setting static DNS, we might need to set EnableDHCP to false,
             # or the API might handle it. For now, just ensure key exists if needed.
             # payload_for_post['Ipv4Configuration']['EnableDHCP'] = primary_adapter_config.get('Ipv4Configuration',{}).get('EnableDHCP', True) # Carry over
             pass


        # Optionally, ensure 'Enable' for Ipv4Configuration is true if not already
        if 'Enable' not in payload_for_post['Ipv4Configuration']:
            payload_for_post['Ipv4Configuration']['Enable'] = True


        self.logger.debug(f"Payload for ConfigureNetworkAdapter (DNS update for {interface_name_for_log}): {json.dumps(payload_for_post, indent=2)}")
        
        return self.configure_network_adapter(payload_for_post)
    #----------------------------------New code
    
     # --- AD Provider Configuration ---
    def configure_ad_provider(self, ad_config_payload: Dict) -> Optional[int]:
        endpoint = constants.API_ENDPOINTS.get('ad_provider_config', "/api/AccountService/ExternalAccountProvider/ADAccountProvider")
        provider_name = ad_config_payload.get("Name", "Unknown AD Provider")
        self.logger.info(f"Configuring AD Provider '{provider_name}'...")
        try:
            response = self._send_api_request('POST', endpoint, json_data=ad_config_payload)
            if response and isinstance(response, dict) and response.get('Id') is not None:
                provider_id = int(response['Id'])
                self.logger.info(f"AD Provider '{provider_name}' configured. ID: {provider_id}")
                return provider_id
            self.logger.error(f"AD Provider '{provider_name}' config response missing ID. Response: {response}")
            return None
        except OmeApiError as e:
            self.logger.error(f"API error configuring AD Provider '{provider_name}': {e.message}")
            return None
        except (ValueError, TypeError) as e:
            self.logger.error(f"Error parsing Provider ID for '{provider_name}': {e}")
            return None

    def test_ad_provider_connection(self, test_payload: Dict) -> bool:
        endpoint = constants.API_ENDPOINTS.get('ad_provider_test_connection', "/api/AccountService/ExternalAccountProvider/Actions/ExternalAccountProvider.TestADConnection")
        provider_id = test_payload.get("Id", "Unknown")
        self.logger.info(f"Testing AD connection for Provider ID: {provider_id}...")
        try:
            # If successful, _send_api_request will not raise OmeApiError for 2xx codes.
            # A 204 (None response) or a 200 (potentially with a success body) means test passed.
            self._send_api_request('POST', endpoint, json_data=test_payload)
            self.logger.info(f"AD connection test for Provider ID {provider_id} reported success.")
            return True
        except OmeApiError as e:
            self.logger.error(f"AD connection test for Provider ID {provider_id} failed: {e.message}")
            return False

    # --- NTP Configuration ---
    def set_ntp_configuration(self, ntp_payload: Dict) -> bool:
        endpoint = constants.API_ENDPOINTS.get('ntp_config', "/api/ApplicationService/Network/TimeConfiguration")
        self.logger.info(f"Setting NTP configuration: {ntp_payload}")
        try:
            self._send_api_request('PUT', endpoint, json_data=ntp_payload)
            self.logger.info("NTP configuration updated successfully.")
            return True
        except OmeApiError as e:
            self.logger.error(f"API error setting NTP configuration: {e.message}")
            return False

    # --- DNS Configuration ---
    def get_network_adapter_configurations(self) -> Optional[List[Dict]]:
        endpoint = constants.API_ENDPOINTS.get('get_adapter_configs', "/api/ApplicationService/Network/AdapterConfigurations")
        self.logger.info("Fetching network adapter configurations...")
        try:
            response = self._send_api_request('GET', endpoint)
            if isinstance(response, dict) and response.get('@odata.context') and isinstance(response.get('value'), list):
                return response['value']
            elif isinstance(response, list): return response
            self.logger.warning(f"Unexpected response for adapter configurations: {response}")
            return None
        except OmeApiError as e:
            self.logger.error(f"API error fetching adapter configurations: {e.message}")
            return None

    def configure_network_adapter(self, adapter_config_payload: Dict) -> Tuple[bool, Optional[str]]:
        endpoint = constants.API_ENDPOINTS.get('configure_network_adapter_action', "/api/ApplicationService/Actions/Network.ConfigureNetworkAdapter")
        if_name = adapter_config_payload.get("InterfaceName", "Unknown Interface")
        self.logger.info(f"Configuring network adapter '{if_name}'...")
        try:
            response = self._send_api_request('POST', endpoint, json_data=adapter_config_payload)
            if response and isinstance(response, dict) and response.get('Id') is not None: # Job ID
                job_id = str(response['Id'])
                self.logger.info(f"Network adapter config job for '{if_name}' submitted. Job ID: {job_id}")
                return True, job_id
            # If API returns 200/204 without job ID for sync success
            elif response is None or isinstance(response, dict):
                 self.logger.info(f"Network adapter '{if_name}' config request accepted (sync or no job ID).")
                 return True, None 
            self.logger.error(f"Network adapter config for '{if_name}' response missing Job ID. Response: {response}")
            return False, None
        except OmeApiError as e:
            self.logger.error(f"API error configuring network adapter '{if_name}': {e.message}")
            return False, None

    def configure_network_adapter_dns(self, preferred_dns: str, alternate_dns: Optional[str]) -> Tuple[bool, Optional[str]]:
        self.logger.info(f"Attempting to configure DNS. Preferred: {preferred_dns}, Alternate: {alternate_dns or 'None'}")
        adapters = self.get_network_adapter_configurations()
        if not adapters:
            self.logger.error("Could not retrieve adapter configs for DNS setup.")
            return False, None
        primary_adapter_config = next((adapter for adapter in adapters if adapter.get("PrimaryInterface") is True), None)
        if not primary_adapter_config:
            self.logger.error("No primary network adapter found for DNS setup.")
            return False, None
        
        if_name = primary_adapter_config.get('InterfaceName', 'UnknownPrimary')
        self.logger.info(f"Found primary adapter: {if_name}")
        payload = {key: value for key, value in primary_adapter_config.items() if not key.startswith('@odata')}
        if 'Ipv4Configuration' not in payload or not isinstance(payload.get('Ipv4Configuration'), dict):
            payload['Ipv4Configuration'] = {}
        
        payload['Ipv4Configuration']['UseDHCPForDNSServerNames'] = False
        payload['Ipv4Configuration']['StaticPreferredDNSServer'] = preferred_dns
        payload['Ipv4Configuration']['StaticAlternateDNSServer'] = alternate_dns if alternate_dns else ""
        if 'Enable' not in payload['Ipv4Configuration']: payload['Ipv4Configuration']['Enable'] = True

        self.logger.debug(f"Payload for ConfigureNetworkAdapter (DNS for {if_name}): {json.dumps(payload, indent=2)}")
        return self.configure_network_adapter(payload)

    def get_job_details(self, job_id: Union[str, int]) -> Optional[Dict]:
        endpoint = constants.API_ENDPOINTS.get('get_job_by_id_simple', f"/api/JobService/Jobs/{job_id}").format(job_id=str(job_id))
        self.logger.debug(f"Fetching details for Job ID: {job_id}...")
        try:
            response = self._send_api_request('GET', endpoint)
            if isinstance(response, dict) and "Id" in response and (str(response["Id"]) == str(job_id)):
                return response
            self.logger.warning(f"Unexpected response or ID mismatch for job {job_id}: {response}")
            return None
        except OmeApiError as e:
            if e.status_code == 404: self.logger.warning(f"Job ID {job_id} not found.")
            else: self.logger.error(f"API error fetching job {job_id}: {e.message}")
            return None

    # --- Plugin Configuration ---
    def update_console_plugins(self, plugins_action_payload: Dict) -> bool:
        endpoint = constants.API_ENDPOINTS.get('update_plugins_action', "/api/PluginService/Actions/PluginService.UpdateConsolePlugins")
        self.logger.info(f"Updating console plugins: {json.dumps(plugins_action_payload, indent=2)[:200]}...")
        try:
            self._send_api_request('POST', endpoint, json_data=plugins_action_payload)
            self.logger.info("Plugin update request submitted successfully.")
            return True # Assuming success if no error. Monitor job if API returns job ID.
        except OmeApiError as e:
            self.logger.error(f"API error updating console plugins: {e.message}")
            return False

    # --- CSR Generation ---
    def generate_csr(self, csr_payload: Dict) -> Optional[str]:
        endpoint = constants.API_ENDPOINTS.get('generate_csr_action', "/api/ApplicationService/Actions/ApplicationService.GenerateCSR")
        self.logger.info(f"Generating CSR with payload: {csr_payload}")
        try:
            response = self._send_api_request('POST', endpoint, json_data=csr_payload)
            if isinstance(response, dict) and isinstance(response.get("CertificateSigningRequest"), str):
                self.logger.info("CSR generated successfully.")
                return response["CertificateSigningRequest"]
            elif isinstance(response, str) and "-----BEGIN CERTIFICATE REQUEST-----" in response: # Raw CSR
                self.logger.info("CSR generated successfully (raw text response).")
                return response
            self.logger.error(f"CSR response missing 'CertificateSigningRequest' string or unexpected format. Response: {response}")
            return None
        except OmeApiError as e:
            self.logger.error(f"API error generating CSR: {e.message}")
            return None
