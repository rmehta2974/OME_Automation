# -*- coding: utf-8 -*-
"""
OME Client module for handling authentication and REST API interactions with
Dell OpenManage Enterprise. Contains the main OME client class.
"""

# __version__ = "1.10.23" # Previous Version
__version__ = "1.10.24" # Updated add_scope_to_ad_group payload to use "UserId" and "Groups" (list).

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history from v1.10.23) ...
# 2025-05-15 | 1.10.23 | Rahul Mehta     | search_ad_group_in_ome_by_name payload key for username is "UserName".
#                                   | search_ad_group_in_ome_by_name expects "ObjectGuid" in response.
#                                   | import_ad_group payload is now a list containing one dict with specified fields.
#                                   | get_imported_ad_group_by_guid renamed to get_imported_ad_account_by_username, iterates all accounts.
#                                   | add_scope_to_ad_group payload uses "userid" and "groupid".
# 2025-05-15 | 1.10.24 | Rahul Mehta     | Changed add_scope_to_ad_group payload to use "UserId" and "Groups" (list of int IDs).
#                                   | Method signature changed to accept a list of static group IDs.

import requests
import logging
import json
import socket
from typing import Dict, List, Optional, Tuple, Any, Union
import urllib.parse

# Use the version of constants.py that is currently in context (constants_v1_2_3_final)
import constants

logger = logging.getLogger(__name__)

class AuthenticationError(Exception): pass
class OmeApiError(Exception):
    def __init__(self, message: str, status_code: int, response_body: Optional[Union[Dict, List, str]] = None):
        super().__init__(message); self.status_code = status_code; self.response_body = response_body
        logging.getLogger(__name__).error(f"OME API Error ({status_code}): {message}")
        if response_body: logging.getLogger(__name__).debug(f"Error Body: {response_body}")

class OmeClient:
    def __init__(self, url: str, username: str, password: str):
        self.logger = logging.getLogger(__name__)
        if not url.startswith('http'): self.url = 'https://' + url; self.logger.warning(f"OME URL '{url}' no scheme, assuming '{self.url}'.")
        else: self.url = url
        self.url = self.url.rstrip('/')
        self.username = username; self.password = password; self.session = requests.Session()
        self.session.verify = False; requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning); self.logger.warning("SSL verify disabled.")
        self._auth_token: Optional[str] = None

    def authenticate(self):
        auth_endpoint = constants.API_ENDPOINTS.get('auth')
        if not auth_endpoint: raise ValueError("Auth endpoint 'auth' missing.")
        auth_url = f"{self.url}{auth_endpoint}"
        payload = {'UserName': self.username, 'Password': self.password}; headers = {'Content-Type': 'application/json'}
        self.logger.info(f"Authenticating with OME at {self.url}...")
        try:
            response = self.session.post(auth_url, headers=headers, data=json.dumps(payload), verify=self.session.verify)
            if response.status_code in [200, 201]:
                self._auth_token = response.headers.get('X-Auth-Token')
                if not self._auth_token: raise AuthenticationError("Auth OK but no token.")
                self.session.headers.update({'X-Auth-Token': self._auth_token}); self.logger.info(f"Auth OK (Status: {response.status_code}).")
            elif response.status_code == 401: raise AuthenticationError("Invalid credentials.")
            else: raise AuthenticationError(f"Auth failed, status: {response.status_code}.")
        except Exception as e: self.logger.error(f"Auth error: {e}"); raise e

    def _send_api_request(self, method: str, endpoint: str, json_data: Optional[Union[Dict, List]] = None, params: Optional[Dict] = None) -> Optional[Union[Dict, List, str]]:
        if not endpoint.startswith('/'): base_url = f"{self.url}/{endpoint}"
        else: base_url = f"{self.url}{endpoint}"
        request_url = base_url; actual_params_for_requests_lib = None
        if method.upper() == 'GET' and params:
            query_components = []
            for key, value in params.items():
                str_value = str(value)
                safe_chars = "()/:=" if key == '$filter' else ""
                encoded_value = urllib.parse.quote(str_value, safe=safe_chars)
                encoded_key = urllib.parse.quote(key, safe="")
                query_components.append(f"{encoded_key}={encoded_value}")
            if query_components: request_url = f"{base_url}?{'&'.join(query_components)}"
            actual_params_for_requests_lib = None; self.logger.debug(f"Manual GET URL: {request_url}")
        else: actual_params_for_requests_lib = params
        headers = {'Content-Type': 'application/json'}
        self.logger.debug(f"API Request: {method} {request_url}, Params: {actual_params_for_requests_lib}, Body: {json.dumps(json_data) if json_data else 'None'}")
        try:
            response = self.session.request(method, request_url, json=json_data, params=actual_params_for_requests_lib, headers=headers, verify=self.session.verify)
            self.logger.debug(f"API Response Status: {response.status_code}")
            if 200 <= response.status_code < 300:
                if response.status_code == 204: return None
                try: return response.json()
                except json.JSONDecodeError: return response.text
            else: raise OmeApiError(f"API Error {response.status_code}", response.status_code, response.text)
        except requests.exceptions.RequestException as e: self.logger.error(f"Connection error: {e}"); raise e
        except OmeApiError as e: raise e
        except Exception as e: self.logger.error(f"Unexpected API req error: {e}", exc_info=True); raise e

    # --- Static Group Methods ---
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
                self.logger.error(f"API endpoint '{endpoint_key}' not defined. Cannot check group membership.")
            else:
                endpoint=constants.API_ENDPOINTS[endpoint_key].format(group_id=target_group_id)
                filter_str: Optional[str]=None
                escaped_val_for_odata_literal = str(search_value).replace("'", "''")
                params_for_group_check: Dict[str, Any] = {}
                device_found_in_group = False
                
                if current_identifier_type == 'device-ip':
                    filter_str = f"DeviceManagement/any(a:a/NetworkAddress eq '{escaped_val_for_odata_literal}')"
                elif current_identifier_type == 'servicetag':
                    filter_str = f"DeviceServiceTag eq '{escaped_val_for_odata_literal}'"
                elif current_identifier_type == 'device-id':
                    filter_str = f"Id eq {search_value}"
                else:
                    self.logger.error(f"Unsupported type '{current_identifier_type}' for group membership check.")

                if filter_str:
                    try:
                        params_for_group_check = {'$filter': filter_str, '$count': 'true', '$top': '0'}
                        self.logger.debug(f"Group membership check: GET {endpoint} with params {params_for_group_check}")
                        resp = self._send_api_request('GET', endpoint, params=params_for_group_check)

                        if resp and isinstance(resp, dict):
                            count_val = resp.get('@odata.count')
                            if count_val is not None:
                                try:
                                    if int(count_val) > 0: device_found_in_group = True
                                except (ValueError, TypeError): self.logger.warning(f"Could not parse @odata.count '{count_val}' for {current_identifier_type} check.")
                            else: self.logger.warning(f"{current_identifier_type} check for group {target_group_id} missing '@odata.count'. Response: {resp}")
                        else: self.logger.warning(f"Unexpected response for group membership check (filter: {filter_str}). Response: {resp}")
                            
                        if device_found_in_group:
                            self.logger.info(f"Device '{identifier_value}' ({identifier_type}) already in target group '{target_group_name}'. Skipping.")
                            return None
                            
                    except OmeApiError as api_err:
                         if api_err.status_code != 404: self.logger.error(f"API error checking group {target_group_id}: {api_err}. Proceeding.")
                         else: self.logger.debug(f"Target group {target_group_id} not found (404) during membership check.")
                    except Exception as e: self.logger.error(f"Error checking group {target_group_id}: {e}. Proceeding.", exc_info=True)
        
        self.logger.debug(f"Device not in target group or check skipped. Performing general search for '{search_value}' ({current_identifier_type})...")
        filter_str=None
        escaped_val_for_odata_literal = str(search_value).replace("'", "''")
        if current_identifier_type == 'device-ip': filter_str = f"DeviceManagement/any(a:a/NetworkAddress eq '{escaped_val_for_odata_literal}')"
        elif current_identifier_type == 'servicetag': filter_str = f"DeviceServiceTag eq '{escaped_val_for_odata_literal}'"
        elif current_identifier_type == 'device-id': filter_str = f"Id eq {search_value}"
        
        if filter_str:
            try:
                endpoint_key = 'devices'
                if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"Endpoint '{endpoint_key}' missing."); return None
                params={'$filter':filter_str,'$top':'1','$select':'Id'};
                self.logger.debug(f"General device search: GET {constants.API_ENDPOINTS[endpoint_key]} with params {params}")
                resp=self._send_api_request('GET',constants.API_ENDPOINTS[endpoint_key],params=params)
                if resp and isinstance(resp,dict) and 'value' in resp and resp['value']:
                    dev_id_raw = resp['value'][0].get('Id')
                    if dev_id_raw is not None: return str(dev_id_raw)
                    else: self.logger.error(f"Device found globally for '{search_value}' but its ID is null/missing."); return None
                self.logger.warning(f"Device not found globally: {current_identifier_type} '{search_value}' (Original: '{identifier_value}' type '{identifier_type}').")
            except Exception as e: self.logger.error(f"Error in general device search for '{search_value}': {e}", exc_info=True)
        return None

    def get_group_by_name(self, group_name: str) -> Optional[Dict]:
        endpoint_key = 'groups'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.debug(f"Searching for group named '{group_name}'...")
        escaped_name_for_odata_literal = group_name.replace("'", "''")
        filter_str = f"Name eq '{escaped_name_for_odata_literal}'"
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

    def create_static_group(self, group_name: str, parent_id: Optional[int] = None) -> Optional[str]:
        endpoint_key = 'create_group'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); raise KeyError("Endpoint 'create_group' missing.")
        if parent_id is None: self.logger.error(f"ParentId is required for creating group '{group_name}'."); return None
        self.logger.info(f"Attempting to create static group '{group_name}' under Parent ID: {parent_id}...")
        group_model_payload = {
            'Name': group_name, 'Description': group_name,
            'MembershipTypeId': constants.STATIC_GROUP_MEMBERSHIP_TYPE_ID,
            'ParentId': parent_id
        }
        final_payload = {"GroupModel": group_model_payload}
        self.logger.debug(f"Payload for creating group (action: {constants.API_ENDPOINTS[endpoint_key]}): {final_payload}")
        try:
            response_data = self._send_api_request('POST', constants.API_ENDPOINTS[endpoint_key], json_data=final_payload)
            if response_data:
                 new_id_raw = response_data.get('GroupId', response_data.get('Id')) if isinstance(response_data, dict) else \
                              (str(response_data) if isinstance(response_data, (str, int)) else None)
                 if new_id_raw is not None and str(new_id_raw).strip(): return str(new_id_raw).strip()
            self.logger.error(f"Group creation '{group_name}' failed or no ID returned. Response: {response_data}"); return None
        except Exception as e: self.logger.error(f"Error creating group '{group_name}': {e}", exc_info=True); raise e

    def add_devices_to_group(self, group_id: str, device_ids: List[str]):
        if not device_ids: self.logger.info(f"No devices to add to group {group_id}."); return
        endpoint_key = 'add_devices_to_group'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        try: payload = { 'GroupId': int(group_id), 'MemberDeviceIds': [int(did) for did in device_ids] }
        except ValueError: self.logger.error(f"Invalid GroupId/DeviceId for AddMemberDevices."); raise ValueError("Invalid ID format.")
        self.logger.info(f"Adding {len(device_ids)} devices to group {group_id} via action {constants.API_ENDPOINTS[endpoint_key]}...")
        self.logger.debug(f"Payload for AddMemberDevices: {payload}")
        try:
            response_data = self._send_api_request('POST', constants.API_ENDPOINTS[endpoint_key], json_data=payload)
            if response_data is None: self.logger.info(f"Add devices request for group {group_id} completed (204 No Content).")
            elif isinstance(response_data, dict) and 'Id' in response_data: self.logger.info(f"Add devices job created for group {group_id}. Job ID: {response_data['Id']}")
            else: self.logger.info(f"Add devices request sent for group {group_id}. Response: {str(response_data)[:100]}")
        except Exception as e: self.logger.error(f"Error adding devices to group {group_id}: {e}", exc_info=True); raise e

    # --- AD Group Import Related Methods ---
    def get_ad_provider_id_by_name(self, ad_provider_name: str) -> Optional[int]:
        endpoint_key = 'external_account_providers'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.debug(f"Finding AD Provider ID for name: '{ad_provider_name}' using {constants.API_ENDPOINTS[endpoint_key]}...")
        try:
            response_data = self._send_api_request('GET', constants.API_ENDPOINTS[endpoint_key])
            if response_data and isinstance(response_data, dict) and 'value' in response_data and isinstance(response_data['value'], list):
                for provider in response_data['value']:
                    if provider.get('Name') == ad_provider_name:
                        pid_raw = provider.get('Id')
                        if pid_raw is not None:
                            try: return int(pid_raw)
                            except (ValueError, TypeError): self.logger.error(f"AD Provider ID '{pid_raw}' not valid int."); return None
                        else: self.logger.warning(f"AD Provider '{ad_provider_name}' found but missing ID."); return None
                self.logger.warning(f"AD Provider '{ad_provider_name}' not found.")
            else: self.logger.warning(f"Failed to retrieve AD Providers or unexpected response: {response_data}")
        except Exception as e: self.logger.error(f"Error retrieving AD provider ID for '{ad_provider_name}': {e}", exc_info=True)
        return None

    def search_ad_group_in_ome_by_name(self, ad_provider_id: int, ad_group_name: str, ad_username: str, ad_password: str) -> Optional[Dict]:
        endpoint_key = 'search_ad_groups_in_ome'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.debug(f"Searching AD group '{ad_group_name}' via OME Provider ID {ad_provider_id} using AD creds...")
        endpoint = constants.API_ENDPOINTS[endpoint_key];
        payload = {
            "DirectoryServerId": ad_provider_id, "CommonName": ad_group_name,
            "Type": constants.AD_SEARCH_TYPE, "UserName": ad_username, "Password": ad_password
        }
        self.logger.debug(f"Payload for AD Group Search Action ({endpoint}): {payload}")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=payload)
            found_groups: List[Dict] = []
            if response_data and isinstance(response_data, dict) and 'value' in response_data and isinstance(response_data['value'], list): found_groups = response_data['value']
            elif response_data and isinstance(response_data, list): found_groups = response_data
            if found_groups:
                group_info = found_groups[0]
                if group_info.get('ObjectGuid'): self.logger.info(f"Found AD group '{ad_group_name}' GUID '{group_info.get('ObjectGuid')}' via OME."); return group_info
                else: self.logger.error(f"AD group '{ad_group_name}' found but missing 'ObjectGuid'."); return None
            else: self.logger.warning(f"AD group '{ad_group_name}' not found via OME search (Provider ID {ad_provider_id})."); return None
        except Exception as e: self.logger.error(f"Error searching AD group '{ad_group_name}' via OME: {e}", exc_info=True); return None

    def get_role_id_by_name(self, role_name: str) -> Optional[str]:
        endpoint_key = 'roles'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.debug(f"Fetching all roles from {constants.API_ENDPOINTS[endpoint_key]} to find '{role_name}'...")
        try:
            response_data = self._send_api_request('GET', constants.API_ENDPOINTS[endpoint_key])
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
        endpoint_key = 'import_ad_group'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.info(f"Importing AD group '{ad_group_name}' (ObjectGuid: {ad_object_guid}, Provider {ad_provider_id}, Role {role_id}) as OME Account...")
        endpoint = constants.API_ENDPOINTS[endpoint_key];
        group_payload_dict = {
            "UserTypeId": 2, "DirectoryServiceId": ad_provider_id, "Description": ad_group_name,
            "Name": ad_group_name, "Password": "", "UserName": ad_group_name,
            "RoleId": role_id, "Locked": False, "Enabled": True, "ObjectGuid": ad_object_guid
        }
        final_payload = [group_payload_dict] # Payload is a list containing the dict
        self.logger.debug(f"Payload for AD Group Import as Account (action: {endpoint}): {final_payload}")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=final_payload)
            if response_data:
                 new_id_raw = None
                 if isinstance(response_data, list) and response_data: # If response is a list
                     first_result = response_data[0]
                     if isinstance(first_result, dict): new_id_raw = first_result.get('Id')
                 elif isinstance(response_data, dict): new_id_raw = response_data.get('Id')
                 elif isinstance(response_data, (str, int)): new_id_raw = str(response_data)
                 
                 if new_id_raw is not None and str(new_id_raw).strip(): return str(new_id_raw).strip()
            self.logger.error(f"AD group import for '{ad_group_name}' failed or no OME Account ID returned."); return None
        except Exception as e: self.logger.error(f"Error importing AD group '{ad_group_name}': {e}", exc_info=True); raise e

    def get_imported_ad_account_by_username(self, ad_group_as_username: str) -> Optional[Dict]:
        endpoint_key = 'accounts'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); return None
        self.logger.debug(f"Searching OME Accounts for UserName '{ad_group_as_username}'...")
        try:
            response_data = self._send_api_request('GET', constants.API_ENDPOINTS[endpoint_key]) # Fetch all accounts
            all_accounts: List[Dict] = []
            if response_data and isinstance(response_data, dict) and 'value' in response_data and isinstance(response_data['value'], list): all_accounts = response_data['value']
            elif response_data and isinstance(response_data, list): all_accounts = response_data
            if all_accounts:
                for account in all_accounts:
                    if account.get('UserName') == ad_group_as_username:
                        if 'Id' in account and account['Id'] is not None: account['Id'] = str(account['Id'])
                        self.logger.info(f"Found existing OME Account for UserName '{ad_group_as_username}' (ID: {account.get('Id')}).")
                        return account
                self.logger.debug(f"No OME Account found with UserName '{ad_group_as_username}'.")
            else: self.logger.warning(f"Failed to retrieve OME accounts or no accounts found when searching for '{ad_group_as_username}'.")
        except Exception as e: self.logger.error(f"Error retrieving OME accounts to find by UserName '{ad_group_as_username}': {e}", exc_info=True)
        return None

    def add_scope_to_ad_group(self, ome_account_id: str, static_group_ids: List[str]): # Changed to accept list of IDs
        """Adds static group(s) (scope) to an OME Account (imported AD group)."""
        endpoint_key = 'add_scope_to_ad_group'
        if endpoint_key not in constants.API_ENDPOINTS: self.logger.error(f"API endpoint '{endpoint_key}' missing."); raise KeyError(f"Endpoint '{endpoint_key}' missing.")
        
        if not static_group_ids:
            self.logger.info(f"No static group IDs provided to set scope for OME Account ID '{ome_account_id}'.")
            return

        self.logger.info(f"Adding static group IDs {static_group_ids} as scope to OME Account ID '{ome_account_id}'...")
        endpoint = constants.API_ENDPOINTS[endpoint_key];
        
        # Payload uses "UserId" and "Groups" (list of integers)
        try:
            payload = {
                'UserId': int(ome_account_id),
                'Groups': [int(gid) for gid in static_group_ids]
            }
        except ValueError:
            self.logger.error(f"Invalid AccountID ('{ome_account_id}') or GroupID in list for SetScope. IDs must be integers.")
            raise ValueError("Invalid ID format for SetScope action.")

        self.logger.debug(f"Payload for Add Scope to Account (SetScope action): {payload}")
        try:
            response_data = self._send_api_request('POST', endpoint, json_data=payload)
            if response_data is None: self.logger.info(f"SetScope request for Account ID {ome_account_id} completed (204 No Content).")
            elif isinstance(response_data, dict) and 'Id' in response_data: self.logger.info(f"SetScope job created for Account ID {ome_account_id}. Job ID: {response_data['Id']}")
            else: self.logger.info(f"SetScope request sent for Account ID {ome_account_id}. Response: {str(response_data)[:100]}")
        except Exception as e: self.logger.error(f"Error adding scope to OME Account ID {ome_account_id}: {e}", exc_info=True); raise e
