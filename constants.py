# -*- coding: utf-8 -*-
"""Defines constants"""

# __version__ = "1.3.0" # Previous Version
__version__ = "1.2.1" # Reverted AD Config, kept other v1.2 changes

# Modifications:
# Date       | Version | Author     | Description
## -*- coding: utf-8 -*-
"""Defines constants"""

# __version__ = "1.2.2" # Previous Version
__version__ = "1.2.3" # Added AD credentials for search, AD Search Type

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-12 | 1.2.2   | Rahul Mehta    | Updated API_ENDPOINTS based on user's latest immersive context.
# 2025-05-12 | 1.2.3   | Rahul Mehta    | Re-added AD_USERNAME, AD_PASSWORD. Added AD_SEARCH_TYPE constant. Updated AD_PROVIDER_CLI_MAP for AD creds. Added AD_CRED_REQUIRED_KEYS.

import logging
logger = logging.getLogger(__name__)

# --- Input Definitions ---
OME_AUTH_REQUIRED_KEYS = {'url', 'username', 'password'}
STATIC_GROUP_REQUIRED_KEYS = {'group_name'}
STATIC_GROUP_OPTIONAL_KEYS = {'devices', 'parent_group', 'create', 'identifier_type'}
VALID_IDENTIFIER_TYPES = {'device-ip', 'device-id', 'dns-name', 'servicetag'}

# --- AD Provider Input Definitions ---
AD_PROVIDER_REQUIRED_KEYS_FOR_FIND = {'Name'} # To find the provider by its OME Name
# --- NEW: AD Credentials for performing search via OME ---
AD_CRED_REQUIRED_KEYS = {'Username', 'Password'} # For the AD account itself

# --- AD Import Group Task Input Definitions ---
AD_IMPORT_TASK_REQUIRED_KEYS = {'group_name'}
AD_IMPORT_TASK_OPTIONAL_KEYS = {'role_name', 'Scope'}

# --- OME Group Type IDs ---
STATIC_GROUP_MEMBERSHIP_TYPE_ID = 24

# --- Default Values ---
DEFAULT_PARENT_GROUP = 'Static Groups'
DEFAULT_CREATE_FLAG = False
DEFAULT_AD_IMPORT_ROLE = "DEVICE_MANAGER"
AD_SEARCH_TYPE = "AD" # Type for the SearchGroups payload

# --- OME API Endpoints ---
API_ENDPOINTS = {
    'auth': '/api/SessionService/Sessions',
    'devices': '/api/DeviceService/Devices',
    'groups': '/api/GroupService/Groups',
    'group_devices': '/api/GroupService/Groups({group_id})/AllLeafDevices',
    'create_group': '/api/GroupService/Actions/GroupService.CreateGroup',
    'add_devices_to_group': '/api/GroupService/Actions/GroupService.AddMemberDevices',
    'external_account_providers': '/api/AccountService/ExternalAccountProviders/ADAccountProvider',
    # This is an action endpoint. The payload will be critical.
    'search_ad_groups_in_ome': '/api/AccountService/ExternalAccountProviders/ExternalAccountProvider.SearchGroups',
    'import_ad_group': '/api/AccountService/Actions/AccountService.ImportExternalAccountProvider',
    'add_scope_to_ad_group': '/api/AccountService/Actions/AccountService.SetScope',
    'roles': '/api/AccountService/Roles',
    'accounts': '/api/AccountService/Accounts'
}

# --- Reusable Configuration and CLI Mappings ---
OME_CLI_CRED_MAP = {'ome_url': 'url', 'username': 'username', 'password': 'password'}
OME_CRED_CONFIG_SECTION = 'OME'

STATIC_GROUP_CLI_ARG_NAME = 'StaticGroup'
STATIC_GROUP_CONFIG_SECTION = 'StaticGroups'

# AD Provider Name (for finding the OME configured provider)
AD_PROVIDER_FIND_CLI_MAP = {'ad_name': 'Name'}
# AD Provider Credentials (for authenticating to AD *through* OME for search)
AD_CRED_CLI_MAP = {'ad_username': 'Username', 'ad_password': 'Password'}
# Combined map for collecting all AD related info (Provider Name + Credentials for search)
AD_CONFIG_CLI_MAP = {**AD_PROVIDER_FIND_CLI_MAP, **AD_CRED_CLI_MAP}

AD_CONFIG_SECTION = 'ActiveDirectory' # Section in config.json for AD Name and AD creds

AD_IMPORT_GROUP_CLI_ARG_NAME = 'adgroup'
AD_IMPORT_GROUP_CONFIG_SECTION = 'ADImportGroup'
