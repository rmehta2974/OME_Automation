# -*- coding: utf-8 -*-
"""
OME Client module for handling authentication and REST API interactions with
Dell OpenManage Enterprise. Contains the main OME client class.
"""

# __version__ = "1.10.1" # Previous Version (where AD config placeholders were removed)
__version__ = "1.10.2" # Corrected URL parameter encoding

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (Include previous relevant history) ...
# 2025-05-06 | 1.10.1  | Gemini     | Removed placeholder configure_ad_provider and validate_ad_provider_connection methods.
# 2025-05-11 | 1.10.2  | Gemini     | Ensured all GET query parameters are manually URL-encoded with %20 for spaces.

import requests
import logging
import json
import socket
from typing import Dict, List, Optional, Tuple, Any, Union
import urllib.parse # Needed for manual filter encoding

import constants # Assuming constants.py is in the same directory

logger = logging.getLogger(__name__)

# --- Custom Exceptions ---
class AuthenticationError(Exception):
    """Custom exception for OME authentication failures."""
    pass

class OmeApiError(Exception):
    """Custom exception for non-authentication OME API errors."""
    def __init__(self, message: str, status_code: int, response_body: Optional[Union[Dict, List, str]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body
        local_logger = logging.getLogger(__name__)
        local_logger.error(f"OME API Error ({status_code}): {message}")
        if response_body:
             local_logger.debug(f"OME API Error Response Body: {response_body}")

# --- OME Client Class ---
class OmeClient:
    def __init__(self, url: str, username: str, password: str):
        self.logger = logging.getLogger(__name__)
        if not url.startswith('http'):
            self.url = 'https://' + url
            self.logger.warning(f"OME URL '{url}' does not specify scheme, assuming '{self.url}'.")
        else: self.url = url
        self.url = self.url.rstrip('/')
        self.username = username; self.password = password; self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.logger.warning("SSL verification is disabled. This is insecure for production environments.")
        self._auth_token: Optional[str] = None

    def authenticate(self):
        auth_endpoint = constants.API_ENDPOINTS.get('auth')
        if not auth_endpoint: raise ValueError("Authentication endpoint 'auth' not defined in constants.")
        auth_url = f"{self.url}{auth_endpoint}"
        payload = {'UserName': self.username, 'Password': self.password}
        headers = {'Content-Type': 'application/json'}
        self.logger.info(f"Authenticating with OME at {self.url}...")
        try:
            response = self.session.post(auth_url, headers=headers, data=json.dumps(payload), verify=self.session.verify)
            self.logger.debug(f"Auth response status code: {response.status_code}")
            if response.status_code in [200, 201]:
                self._auth_token = response.headers.get('X-Auth-Token')
                if not self._auth_token:
                    self.logger.error("Authentication successful but X-Auth-Token not found.")
                    raise AuthenticationError("Authentication successful, but X-Auth-Token not received.")
                self.session.headers.update({'X-Auth-Token': self._auth_token})
                self.logger.info(f"Authentication successful (Status: {response.status_code}).")
            elif response.status_code == 401:
                 self.logger.error(f"Authentication failed: Invalid credentials (Status: 401).")
                 raise AuthenticationError("Invalid OME username or password.")
            else:
                self.logger.error(f"Authentication failed with status: {response.status_code}.")
                raise AuthenticationError(f"Authentication failed with status code {response.status_code}.")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Connection error during OME authentication: {e}"); raise e
        except AuthenticationError as e: raise e
        except Exception as e:
             self.logger.error(f"Unexpected error during authentication: {e}", exc_info=True)
             raise AuthenticationError(f"Unexpected error during authentication: {e}")

    def _send_api_request(self, method: str, endpoint: str, json_data: Optional[Dict] = None, params: Optional[Dict] = None) -> Optional[Union[Dict, List, str]]:
        """
        Helper method to send API request, ensuring correct URL encoding for GET parameters.
        Spaces in parameter values will be encoded as %20.
        """
        if not endpoint.startswith('/'):
            base_url = f"{self.url}/{endpoint}"
        else:
            base_url = f"{self.url}{endpoint}"

        request_url = base_url
        # This will be passed to requests.request(). It's None if we manually build the query string.
        actual_params_for_requests_lib = None

        if method.upper() == 'GET' and params:
            self.logger.debug(f"Manually encoding GET parameters: {params}")
            query_components = []
            for key, value in params.items():
                # Ensure value is a string before quoting
                str_value = str(value)
                if key == '$filter':
                    # For $filter, be specific with safe characters for OData syntax
                    # This ensures spaces become %20, and OData chars like '():/= are preserved.
                    encoded_value = urllib.parse.quote(str_value, safe="()/:='")
                else:
                    # For other parameters (e.g., $top, $select, $count),
                    # a more general quoting is usually fine.
                    # urllib.parse.quote with empty safe string will encode most things,
                    # including typical non-alphanumeric characters, using %XX.
                    # Spaces become %20.
                    encoded_value = urllib.parse.quote(str_value, safe="")
                query_components.append(f"{urllib.parse.quote(key, safe='')}={encoded_value}") # Also encode the key

            if query_components:
                request_url = f"{base_url}?{'&'.join(query_components)}"
            # Since we've built the full query string, don't pass params to requests lib
            actual_params_for_requests_lib = None
            self.logger.debug(f"Manually constructed GET URL: {request_url}")
        else:
            # For POST/PUT etc., or GET without params, params are passed as is to requests
            # (usually None for POST/PUT where data is in json_data)
            actual_params_for_requests_lib = params
            self.logger.debug(f"Using requests default parameter handling (if any). URL: {request_url}, Params: {actual_params_for_requests_lib}")

        headers = {'Content-Type': 'application/json'}
        self.logger.debug(f"API Request Final: {method} {request_url}")
        root_logger = logging.getLogger()
        if root_logger.isEnabledFor(logging.DEBUG):
            root_logger.debug(f"Request Headers: {self.session.headers}")
            if json_data: root_logger.debug(f"Request JSON Body: {json.dumps(json_data)}")

        try:
            response = self.session.request(
                method,
                request_url, # URL with manually encoded query string for GET
                json=json_data,
                params=actual_params_for_requests_lib, # Should be None if query string was built
                headers=headers,
                verify=self.session.verify
            )
            self.logger.debug(f"API Response Status: {response.status_code} for {method} {request_url}")

            if 200 <= response.status_code < 300:
                if response.status_code == 204: return None
                try: return response.json()
                except json.JSONDecodeError:
                    self.logger.warning(f"API call {request_url} status {response.status_code}, body not JSON. Body: {response.text[:200]}...")
                    return response.text
            elif response.status_code == 401: raise OmeApiError("Unauthorized", 401, response.text)
            elif response.status_code == 404: raise OmeApiError("Not Found", 404, response.text)
            else: raise OmeApiError(f"API Error {response.status_code}", response.status_code, response.text)

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Connection error: {e}"); raise e
        except OmeApiError as e: raise e
        except Exception as e:
            self.logger.error(f"Unexpected API req error: {e}", exc_info=True); raise e

    # --- Static Group Related Methods ---
    def find_device_id(self, identifier_type: str, identifier_value: str, target_group_id: Optional[str]=None, target_group_name: Optional[str]=None, check_target_group_membership: bool=False) -> Optional[str]:
        search_value=identifier_value; current_identifier_type=identifier_type
        if identifier_type == 'dns-name':
            self.logger.debug(f"Resolving DNS name '{identifier_value}'...")
            try:
                addr_info=socket.getaddrinfo(identifier_value, None, socket.AF_INET); ip_address = addr_info[0][4][0]
                self.logger.info(f"Resolved DNS '{identifier_value}' to IP: {ip_address}")
            except socket.gaierror as e: self.logger.error(f"Failed DNS resolution for '{identifier_value}': {e}"); return None
            except IndexError: self.logger.error(f"DNS resolution for '{identifier_value}' no IPv4."); return None
            except Exception as e: self.logger.error(f"Unexpected DNS error for '{identifier_value}': {e}", exc_info=True); return None
            current_identifier_type='device-ip'; search_value=ip_address

        if check_target_group_membership and target_group_id:
            self.logger.debug(f"Checking if device '{search_value}' ({current_identifier_type}) is in target group '{target_group_name}' (ID: {target_group_id})...")
            endpoint_key = 'group_devices'
            if endpoint_key not in constants.API_ENDPOINTS:
                self.logger.error(f"API endpoint '{endpoint_key}' not defined in constants. Cannot check group membership.")
            else:
                endpoint=constants.API_ENDPOINTS[endpoint_key].format(group_id=target_group_id)
                filter_str: Optional[str]=None
                escaped_val=str(search_value).replace("'","''")

                if current_identifier_type == 'device-ip': filter_str = f"DeviceManagement/any(a:a/NetworkAddress eq '{escaped_val}')"
                elif current_identifier_type == 'servicetag': filter_str = f"DeviceServiceTag eq '{escaped_val}'"
                elif current_identifier_type == 'device-id': filter_str = f"Id eq {escaped_val}"
                else: self.logger.error(f"Unsupported type '{current_identifier_type}' for group membership check.")

                if filter_str:
                    try:
                        params={'$filter':filter_str,'$count':'true','$top':'0'}
                        resp=self._send_api_request('GET',endpoint,params=params)
                        if resp and isinstance(resp,dict):
                            count_val=resp.get('@odata.count')
                            if count_val is not None:
                                try:
                                    count = int(count_val)
                                    if count > 0:
                                        self.logger.info(f"Device '{identifier_value}' ({identifier_type}) already in target group '{target_group_name}'. Skipping.")
                                        return None
                                except (ValueError, TypeError): self.logger.warning(f"Could not parse @odata.count '{count_val}' as int for group {target_group_id}")
                            else: self.logger.warning(f"Group membership check for {target_group_id} missing '@odata.count'.")
                    except OmeApiError as api_err:
                         if api_err.status_code != 404: self.logger.error(f"API error checking group {target_group_id}: {api_err}. Proceeding.")
                         else: self.logger.debug(f"Target group {target_group_id} not found (404) during membership check.")
                    except Exception as e: self.logger.error(f"Error checking group {target_group_id}: {e}. Proceeding.", exc_info=True)
        elif target_group_id:
             self.logger.debug("Group is new or check_target_group_membership is False. Skipping target group membership check.")

        self.logger.debug(f"Performing general search for device '{search_value}' ({current_identifier_type})...")
        filter_str=None; escaped_val=str(search_value).replace("'","''")
        if current_identifier_type == 'device-ip': filter_str = f"DeviceManagement/any(a:a/NetworkAddress eq '{escaped_val}')"
        elif current_identifier_type == 'servicetag': filter_str = f"DeviceServiceTag eq '{escaped_val}'"
        elif current_identifier_type == 'device-id': filter_str = f"Id eq {escaped_val}"
        else: self.logger.error(f"Unsupported type '{current_identifier_type}' for general search."); return None

        if filter_str:
            try:
                endpoint_key = 'devices'
                if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
                params={'$filter':filter_str,'$top':'1','$select':'Id'}
                resp=self._send_api_request('GET',constants.API_ENDPOINTS[endpoint_key],params=params)
                if resp and isinstance(resp,dict) and 'value' in resp and resp['value']:
                    dev_id_raw = resp['value'][0].get('Id')
                    if dev_id_raw is not None: return str(dev_id_raw)
                    else: self.logger.error(f"Device found globally for '{search_value}' but its ID is null or missing."); return None
                self.logger.warning(f"Device not found globally: {current_identifier_type} '{search_value}' (Original: '{identifier_value}' type '{identifier_type}').")
            except Exception as e: self.logger.error(f"Error in general device search for '{search_value}': {e}", exc_info=True)
        return None

    def get_group_member_ids(self, group_id: str) -> Optional[List[str]]:
        endpoint_key = 'group_devices'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        endpoint = constants.API_ENDPOINTS[endpoint_key].format(group_id=group_id)
        self.logger.debug(f"Retrieving members for group ID '{group_id}' from {endpoint}...")
        try:
            response_data = self._send_api_request('GET', endpoint, params={'$select': 'Id'})
            if response_data and isinstance(response_data, dict) and 'value' in response_data and isinstance(response_data['value'], list):
                return [str(d.get('Id')) for d in response_data['value'] if d.get('Id') is not None]
            self.logger.warning(f"Failed to retrieve members for group ID '{group_id}' or unexpected response.")
        except Exception as e: self.logger.error(f"Error getting members for group {group_id}: {e}", exc_info=True)
        return None

    def get_group_by_name(self, group_name: str) -> Optional[Dict]:
        endpoint_key = 'groups'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.debug(f"Searching for group named '{group_name}'...")
        escaped_name = group_name.replace("'", "''"); filter_str = f"Name eq '{escaped_name}'"
        try:
            response_data = self._send_api_request('GET', constants.API_ENDPOINTS[endpoint_key], params={'$filter': filter_str, '$top': '1'})
            if response_data and isinstance(response_data, dict) and 'value' in response_data and response_data['value']:
                group_data = response_data['value'][0];
                if 'Id' in group_data and group_data['Id'] is not None: group_data['Id'] = str(group_data['Id'])
                self.logger.debug(f"Found group '{group_name}' (ID: {group_data.get('Id')}).")
                return group_data
            self.logger.debug(f"Group '{group_name}' not found.")
        except Exception as e: self.logger.error(f"Error getting group by name '{group_name}': {e}", exc_info=True)
        return None

    def create_static_group(self, group_name: str, parent_group_id: Optional[Union[int, str]] = None) -> Optional[str]:
        endpoint_key = 'groups'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); raise KeyError("Endpoint 'groups' missing.")
        self.logger.info(f"Attempting to create static group '{group_name}'...")
        payload = {
            'Name': group_name, 'Description': f'Created by script {__version__}',
            'MembershipTypeId': constants.STATIC_GROUP_MEMBERSHIP_TYPE_ID, 'ParentId': 0
        }
        if parent_group_id is not None:
             try: payload['ParentId'] = int(parent_group_id)
             except (ValueError, TypeError): self.logger.error(f"Invalid ParentID '{parent_group_id}'. Using root (0)."); payload['ParentId'] = 0
        self.logger.debug(f"Payload for creating group: {payload}")
        try:
            response_data = self._send_api_request('POST', constants.API_ENDPOINTS[endpoint_key], json_data=payload)
            if response_data:
                 new_id_raw = response_data.get('Id') if isinstance(response_data, dict) else (str(response_data) if isinstance(response_data, (str, int)) else None)
                 if new_id_raw is not None:
                    new_id_str = str(new_id_raw).strip()
                    if new_id_str: self.logger.info(f"Created group '{group_name}' ID: {new_id_str}."); return new_id_str
            self.logger.error(f"Group creation '{group_name}' failed or no ID returned.")
            return None
        except Exception as e: self.logger.error(f"Error creating group '{group_name}': {e}", exc_info=True); raise e

    def add_devices_to_group(self, group_id: str, device_ids: List[str]):
        if not device_ids: self.logger.info(f"No devices to add to group {group_id}."); return
        endpoint_key = 'add_devices_to_group'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        endpoint = constants.API_ENDPOINTS[endpoint_key].format(group_id=group_id)
        payload = { 'MemberDeviceIds': device_ids }
        self.logger.info(f"Adding {len(device_ids)} device(s) to group {group_id} via {endpoint}...")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=payload)
            if response_data is None: self.logger.info(f"Add devices request for group {group_id} completed (204 No Content).")
            elif isinstance(response_data, dict) and 'Id' in response_data: self.logger.info(f"Add devices job created for group {group_id}. Job ID: {response_data['Id']}")
            else: self.logger.info(f"Add devices request sent for group {group_id}. Response: {str(response_data)[:100]}")
        except Exception as e: self.logger.error(f"Error adding devices to group {group_id}: {e}", exc_info=True); raise e

    # --- AD Group Import Related Methods ---
    def get_external_account_providers(self) -> Optional[List[Dict]]:
        endpoint_key = 'external_account_providers'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.debug("Retrieving External Account Providers...")
        try:
            response_data = self._send_api_request('GET', constants.API_ENDPOINTS[endpoint_key])
            if response_data and isinstance(response_data, dict) and 'value' in response_data and isinstance(response_data['value'], list):
                self.logger.debug(f"Found {len(response_data['value'])} External Account Provider(s).")
                return response_data['value']
            self.logger.warning("Failed to retrieve External Account Providers or unexpected response.")
        except Exception as e: self.logger.error(f"Error getting external providers: {e}", exc_info=True)
        return None

    def search_ad_group_in_ome_by_name(self, ad_provider_id: str, ad_group_name: str) -> Optional[Dict]:
        endpoint_key = 'search_ad_groups_in_ome'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.debug(f"Searching AD group '{ad_group_name}' via OME Provider ID {ad_provider_id}...")
        endpoint = constants.API_ENDPOINTS[endpoint_key];
        payload = {'ExternalAccountProviderId': ad_provider_id, 'GroupName': ad_group_name} # VERIFY payload
        self.logger.debug(f"Payload for AD Group Search: {payload}")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=payload) # VERIFY method
            if response_data and isinstance(response_data, dict) and 'value' in response_data and isinstance(response_data['value'], list) and response_data['value']:
                 group_info = response_data['value'][0]
                 if group_info.get('Guid'): return group_info
                 else: self.logger.error(f"AD group '{ad_group_name}' found but missing 'Guid'."); return None
            elif response_data and isinstance(response_data, list) and response_data: # If API returns list directly
                 group_info = response_data[0]
                 if group_info.get('Guid'): return group_info
                 else: self.logger.error(f"AD group '{ad_group_name}' found but missing 'Guid'."); return None
            self.logger.warning(f"AD group '{ad_group_name}' not found via OME search or unexpected response.")
        except Exception as e: self.logger.error(f"Error searching AD group '{ad_group_name}' via OME: {e}", exc_info=True)
        return None

    def get_role_id_by_name(self, role_name: str) -> Optional[str]:
        endpoint_key = 'roles'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.debug(f"Searching OME for role named '{role_name}'...")
        escaped_name=role_name.replace("'","''"); filter_str=f"Name eq '{escaped_name}'"
        try:
            response_data = self._send_api_request('GET', constants.API_ENDPOINTS[endpoint_key], params={'$filter': filter_str, '$top': '1'})
            if response_data and isinstance(response_data, dict) and 'value' in response_data and response_data['value']:
                 role_id_raw = response_data['value'][0].get('Id')
                 return str(role_id_raw) if role_id_raw is not None else None
            self.logger.warning(f"OME Role '{role_name}' not found.")
        except Exception as e: self.logger.error(f"Error getting role '{role_name}': {e}", exc_info=True)
        return None

    def import_ad_group(self, ad_provider_id: str, ad_group_guid: str, role_id: str) -> Optional[str]:
        endpoint_key = 'import_ad_group'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.info(f"Importing AD group GUID '{ad_group_guid}' from Provider {ad_provider_id}, Role {role_id}...")
        endpoint = constants.API_ENDPOINTS[endpoint_key];
        payload = {'ExternalAccountProviderId': ad_provider_id, 'AdGroupGuid': ad_group_guid, 'RoleId': role_id} # VERIFY payload
        self.logger.debug(f"Payload for AD Group Import: {payload}")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=payload) # VERIFY method
            if response_data:
                 new_id_raw = response_data.get('Id') if isinstance(response_data, dict) else (str(response_data) if isinstance(response_data, (str, int)) else None)
                 if new_id_raw is not None:
                    new_id_str = str(new_id_raw).strip()
                    if new_id_str: return new_id_str
            self.logger.error(f"AD group import for GUID '{ad_group_guid}' failed or no ID returned from API.")
            return None
        except Exception as e:
            self.logger.error(f"Error importing AD group GUID '{ad_group_guid}': {e}", exc_info=True)
            raise e

    def get_imported_ad_group_by_guid(self, ad_group_guid: str) -> Optional[Dict]:
        endpoint_key = 'groups'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        ad_guid_field_name = 'AdGroupGuid' # VERIFY THIS field name
        self.logger.debug(f"Searching OME for imported AD group with GUID '{ad_group_guid}' using field '{ad_guid_field_name}'...")
        filter_string = f"{ad_guid_field_name} eq '{ad_group_guid}'"
        try:
            response_data = self._send_api_request('GET', constants.API_ENDPOINTS[endpoint_key], params={'$filter': filter_string, '$top': '1'})
            if response_data and isinstance(response_data, dict) and 'value' in response_data and response_data['value']:
                 group_data = response_data['value'][0];
                 if 'Id' in group_data and group_data['Id'] is not None: group_data['Id'] = str(group_data['Id'])
                 self.logger.debug(f"Found imported AD group with GUID '{ad_group_guid}' (OME ID: {group_data.get('Id')}).")
                 return group_data
            self.logger.debug(f"Imported AD group with GUID '{ad_group_guid}' not found in OME.")
        except Exception as e: self.logger.error(f"Error getting imported AD group by GUID '{ad_group_guid}': {e}", exc_info=True)
        return None

    def add_scope_to_ad_group(self, ome_group_id: str, static_group_id: str):
        endpoint_key = 'add_scope_to_ad_group'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        self.logger.info(f"Adding static group ID '{static_group_id}' as scope to OME AD group ID '{ome_group_id}'...")
        endpoint = constants.API_ENDPOINTS[endpoint_key].format(group_id=ome_group_id);
        payload = {'ScopeIds': [static_group_id]} # VERIFY payload
        self.logger.debug(f"Payload for Add Scope: {payload}")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=payload) # VERIFY method
            if response_data is None: self.logger.info(f"Add scope request for AD group {ome_group_id} completed (204 No Content).")
            elif isinstance(response_data, dict) and 'Id' in response_data: self.logger.info(f"Add scope job created for AD group {ome_group_id}. Job ID: {response_data['Id']}")
            else: self.logger.info(f"Add scope request sent for AD group {ome_group_id}. Response: {str(response_data)[:100]}")
        except Exception as e:
            self.logger.error(f"Error adding scope to AD group {ome_group_id}: {e}", exc_info=True)
            raise e
