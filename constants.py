# -*- coding: utf-8 -*-
"""Defines constants for OME automation scripts."""

# __version__ = "1.3.1" # Previous Version
__version__ = "1.3.2" # Consolidated AD Provider configuration into a single config section.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-15 | 1.3.1   | Gemini     | Reverted Static Group creation constants to use original comprehensive definitions.
#            |         |            | Aligned AD Import Group constants with user's original constants.py.
# 2025-05-15 | 1.3.2   | Gemini     | Consolidated AD Provider full configuration to use the existing 'ActiveDirectory'
#            |         |            | config section. Renamed CLI arg for AD full config payload.

import logging
logger = logging.getLogger(__name__)

# --- Input Definitions (Existing from user's constants.py) ---
OME_AUTH_REQUIRED_KEYS = {'url', 'username', 'password'}
STATIC_GROUP_REQUIRED_KEYS = {'group_name'}
STATIC_GROUP_OPTIONAL_KEYS = {'devices', 'parent_group', 'create', 'identifier_type'}
VALID_IDENTIFIER_TYPES = {'device-ip', 'device-id', 'dns-name', 'servicetag'}

# --- AD Provider Input Definitions ---
# For finding an existing provider by name
AD_PROVIDER_REQUIRED_KEYS_FOR_FIND = {'Name'}
# For AD search credentials (used by OME to query AD)
AD_CRED_REQUIRED_KEYS = {'UserName', 'Password'}
# For the full AD Provider configuration payload (when creating/updating the provider in OME)
# These keys are expected within the 'ActiveDirectory' config section or via --ad-configure-parameter
AD_PROVIDER_PAYLOAD_REQUIRED_KEYS = {'Name', 'ServerType', 'ServerName', 'UserName', 'Password', 'ServerPort','GroupDomain', 'NetworkTimeOut', 'SearchTimeOut'}
AD_PROVIDER_PAYLOAD_OPTIONAL_KEYS = {'CertificateValidation', 'CertificateFile'} # Add other optional AD config keys like BindDN, BindPassword if applicable

# --- AD Import Group Task Input Definitions (Existing from user's constants.py) ---
AD_IMPORT_TASK_REQUIRED_KEYS = {'group_name'}
AD_IMPORT_TASK_OPTIONAL_KEYS = {'role', 'scope'}


# --- OME Group Type IDs (Existing from user's constants.py) ---
STATIC_GROUP_MEMBERSHIP_TYPE_ID = 24 # For static groups

# --- Default Values (Existing from user's constants.py) ---
DEFAULT_PARENT_GROUP = 'Static Groups'
DEFAULT_CREATE_FLAG = False
DEFAULT_AD_IMPORT_ROLE = "DEVICE_MANAGER"
AD_SEARCH_TYPE = "AD"

# --- NEW: Configuration Task Input Definitions (for OME Config Manager) ---

# NTP Configuration
NTP_CONFIG_REQUIRED_KEYS = {'EnableNTP', 'PrimaryNTPAddress', 'TimeZone'}
NTP_CONFIG_OPTIONAL_KEYS = {'SecondaryNTPAddress1', 'SecondaryNTPAddress2'}

# DNS Configuration (simple list of servers, validation will check count)
DNS_SERVERS_LIST_MIN_MAX = (1, 2)

# CSR Generation Details
CSR_DETAILS_REQUIRED_KEYS = {'common_name', 'organization', 'locality', 'state_or_province', 'country_code', 'key_size'}
CSR_DETAILS_OPTIONAL_KEYS = {'organizational_unit', 'email_address', 'subject_alternative_names_str'}
VALID_CSR_KEY_SIZES = [2048, 3072, 4096]

# Plugin Action Task
PLUGIN_ACTION_TASK_REQUIRED_KEYS = {'Id', 'Version', 'Action'}
VALID_PLUGIN_ACTIONS = ["Install", "Uninstall", "Enable", "Disable"]


# --- OME API Endpoints (Consolidated) ---
API_ENDPOINTS = {
    'auth': '/api/SessionService/Sessions',
    'devices': '/api/DeviceService/Devices',
    'groups': '/api/GroupService/Groups',
    'group_devices': '/api/GroupService/Groups({group_id})/AllLeafDevices',
    'create_group': '/api/GroupService/Actions/GroupService.CreateGroup',
    'add_devices_to_group': '/api/GroupService/Actions/GroupService.AddMemberDevices',
    'external_account_providers': '/api/AccountService/ExternalAccountProviders/ADAccountProvider',
    'search_ad_groups_in_ome': '/api/AccountService/ExternalAccountProviders/ExternalAccountProvider.SearchGroups',
    'import_ad_group': '/api/AccountService/Actions/AccountService.ImportExternalAccountProvider',
    'add_scope_to_ad_group': '/api/AccountService/Actions/AccountService.SetScope',
    'roles': '/api/AccountService/Roles',
    'accounts': '/api/AccountService/Accounts',
    'ad_provider_config': '/api/AccountService/ExternalAccountProvider/ADAccountProvider',
    'ad_provider_test_connection': '/api/AccountService/ExternalAccountProvider/Actions/ExternalAccountProvider.TestADConnection',
    'ntp_config': '/api/ApplicationService/Network/TimeConfiguration',
    'get_adapter_configs': '/api/ApplicationService/Network/AdapterConfigurations',
    'configure_network_adapter_action': '/api/ApplicationService/Actions/Network.ConfigureNetworkAdapter',
    'get_job_by_id_simple': '/api/JobService/Jobs/{job_id}',
    'update_plugins_action': '/api/PluginService/Actions/PluginService.UpdateConsolePlugins',
    'generate_csr_action': '/api/ApplicationService/Actions/ApplicationService.GenerateCSR',
}

# --- Reusable Configuration and CLI Mappings ---

# OME Credentials
OME_CLI_CRED_MAP = {'ome_url': 'url', 'username': 'username', 'password': 'password'}
OME_CRED_CONFIG_SECTION = 'OME'

# AD Provider Settings (Name for finding, Search Credentials, and Full Configuration Payload)
# The 'ActiveDirectory' section in config.json will hold all these.
# CLI args provide overrides or specific parts.
AD_CONFIG_SECTION = 'ActiveDirectory' # Single config section for all AD related settings.
AD_PROVIDER_FIND_CLI_MAP = {'ad_provider_name': 'Name'} # For --ad-provider-name
AD_CRED_CLI_MAP = {'ad_search_username': 'UserName', 'ad_search_password': 'Password'} # For --ad-search-username/password
# Combined map for utils.collect_and_validate_credentials when fetching Name & Search Creds
AD_NAME_AND_SEARCH_CREDS_CLI_MAP = {**AD_PROVIDER_FIND_CLI_MAP, **AD_CRED_CLI_MAP}

# AD Import Group Tasks
AD_IMPORT_GROUP_CLI_ARG_NAME = 'adgroup'
AD_IMPORT_GROUP_CONFIG_SECTION = 'ADImportGroup'

# Static Group Tasks
STATIC_GROUP_CLI_ARG_NAME = 'StaticGroup'
STATIC_GROUP_CONFIG_SECTION = 'StaticGroups'

# --- CLI Argument Names and Config Section Names for OME Config Manager (Specific Payloads/Inputs) ---

# AD Provider Full Configuration Payload (when creating/updating the provider itself)
# The config section is AD_CONFIG_SECTION ('ActiveDirectory').
AD_PROVIDER_CONFIGURE_PARAMETER_CLI_ARG_NAME = 'ad_configure_parameter' # CLI: --ad-configure-parameter (JSON string for full payload)

# NTP Configuration Payload
NTP_PAYLOAD_CLI_ARG_NAME = 'ntp_payload'
NTP_CONFIG_SECTION = 'NTPConfiguration' # Config: "NTPConfiguration": {...payload...}

# DNS Server List
DNS_SERVERS_CLI_ARG_NAME = 'dns_servers'
DNS_SERVERS_CONFIG_SECTION = 'DNSConfiguration' # Config: "DNSConfiguration": {"servers": ["ip1", "ip2"]}

# CSR Generation Details Payload
CSR_DETAILS_PAYLOAD_CLI_ARG_NAME = 'csr_payload'
CSR_CONFIG_SECTION = 'CSRConfiguration' # Config: "CSRConfiguration": {...payload...}

# Plugin Action Tasks
PLUGIN_ACTION_TASK_CLI_ARG_NAME = 'plugin_action_task'
PLUGIN_TASKS_CONFIG_SECTION = 'PluginActionTasks'
