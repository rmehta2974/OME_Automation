# -*- coding: utf-8 -*-
"""Defines constants"""

# __version__ = "1.3.0" # Previous Version
__version__ = "1.2.1" # Reverted AD Config, kept other v1.2 changes

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-06 | 1.2.0   | Gemini     | Added constants for AD Provider and AD Import Group handling.
# 2025-05-06 | 1.3.0   | Gemini     | Added AD config details, --configure-ad flag, default role. Updated required keys.
# 2025-05-06 | 1.2.1   | Gemini     | Removed constants related to full AD provider configuration (--configure-ad). Kept default role.

import logging
logger = logging.getLogger(__name__)

# --- Input Definitions ---
OME_AUTH_REQUIRED_KEYS = {'url', 'username', 'password'}
STATIC_GROUP_REQUIRED_KEYS = {'group_name'}
STATIC_GROUP_OPTIONAL_KEYS = {'devices', 'parent_group', 'create', 'identifier_type'}
VALID_IDENTIFIER_TYPES = {'device-ip', 'device-id', 'dns-name', 'servicetag'}

# --- AD Provider Input Definitions ---
# Keys required just to *find* an existing provider by Name
AD_PROVIDER_REQUIRED_KEYS_FOR_FIND = {'Name'}

# --- AD Import Group Task Input Definitions ---
AD_IMPORT_TASK_REQUIRED_KEYS = {'group_name'} # role_name is now optional with default
AD_IMPORT_TASK_OPTIONAL_KEYS = {'role_name', 'Scope'} # Name of the static group for scope

# --- OME Group Type IDs ---
STATIC_GROUP_MEMBERSHIP_TYPE_ID = 24

# --- Default Values ---
DEFAULT_PARENT_GROUP = 'Static Groups'
DEFAULT_CREATE_FLAG = False
DEFAULT_AD_IMPORT_ROLE = "Device_Manager" # Default role if not specified in task

# --- OME API Endpoints (ensure needed endpoints are present/correct) ---
API_ENDPOINTS = {
    'auth': '/api/SessionService/Sessions',
    'devices': '/api/DeviceService/Devices',
    'groups': '/api/GroupService/Groups',
    'group_devices': '/api/GroupService/Groups({group_id})/AllLeafDevices',
    'create_group': '/api/GroupService/Actions/GroupService.CreateGroup',
    'add_devices_to_group': '/api/GroupService/Actions/GroupService.AddMemberDevices', # AddMemberDevice Action
    'external_account_providers': '/api/AccountService/ExternalAccountProviders/ADAccountProvider', # PlaceHolder for ADId search in OME and endpoint for same.
    'search_ad_groups_in_ome': '/api/AccountService/ExternalAccountProviders/ExternalAccountProvider.SearchGroups', # Searching a Group in AD Endpoint
    'import_ad_group': '/api/AccountService/Actions/AccountService.ImportExternalAccountProvider', # ADgroup Import endpoint
    'add_scope_to_ad_group': '/api/AccountService/Actions/AccountService.SetScope', # ADGroups are Imported as User, thus adding staticgroups to users.
    'roles': '/api/AccountService/Roles', # Needed
    # Removed placeholders for AD config/validation endpoints
}

# --- Reusable Configuration and CLI Mappings ---
# OME Creds
OME_CLI_CRED_MAP = {'ome_url': 'url', 'username': 'username', 'password': 'password'}
OME_CRED_CONFIG_SECTION = 'OME'

# Static Groups (from main.py)
STATIC_GROUP_CLI_ARG_NAME = 'StaticGroup'
STATIC_GROUP_CONFIG_SECTION = 'StaticGroups'

# --- AD Provider Config Mappings (Simplified) ---
AD_PROVIDER_CONFIG_SECTION = 'ActiveDirectory' # Section name specified by user
# Only need Name for finding
AD_PROVIDER_CLI_MAP = {'ad_name': 'Name'}
AD_PROVIDER_CLI_ARGS = ['ad_name'] # Only need the name arg


# --- AD Import Group Task Mappings ---
AD_IMPORT_GROUP_CLI_ARG_NAME = 'adgroup' # e.g., --adgroup '{...}'
AD_IMPORT_GROUP_CONFIG_SECTION = 'ADImportGroup' # Name from user spec

