# -*- coding: utf-8 -*-
"""Defines constants for OME automation scripts."""

# __version__ = "1.3.9" # Previous Version
__version__ = "1.3.10" # Aligned NTP configuration input keys directly to API payload keys.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-15 | 1.3.9   | Rahul Mehta     | Changed AD_IMPORT_TASK_OPTIONAL_KEYS to {'role', 'scope'} as per user request.
# 2025-05-15 | 1.3.10  | Rahul Mehta     | Updated NTP configuration keys (NTP_CONFIG_REQUIRED_KEYS,
#            |         |            | NTP_CONFIG_OPTIONAL_KEYS) to directly reflect API payload keys
#            |         |            | as per user request. Removed separate user input keys for NTP.

import logging
logger = logging.getLogger(__name__)

# --- Input Definitions ---
OME_AUTH_REQUIRED_KEYS = {'url', 'username', 'password'}
STATIC_GROUP_REQUIRED_KEYS = {'group_name'}
STATIC_GROUP_OPTIONAL_KEYS = {'devices', 'parent_group', 'create', 'identifier_type'}
VALID_IDENTIFIER_TYPES = {'device-ip', 'device-id', 'dns-name', 'servicetag'}

# --- AD Provider Input Definitions ---
AD_PROVIDER_REQUIRED_KEYS_FOR_FIND = {'Name'} 
AD_CRED_REQUIRED_KEYS = {'UserName', 'Password'} 

AD_PROVIDER_PAYLOAD_REQUIRED_KEYS = {
    'Name', 'ServerType', 'ServerName', 
    'UserName', 'Password', 'ServerPort', 
    'NetworkTimeOut', 'SearchTimeOut','GroupDomain'
}
AD_PROVIDER_PAYLOAD_OPTIONAL_KEYS = {
    'CertificateValidation', 
    'CertificateFile'
}

AD_TEST_CONNECTION_PAYLOAD_REQUIRED_KEYS = {
    'Name', 'ServerType', 'ServerName',
    'UserName', 'Password', 
    'ServerPort', 'NetworkTimeOut', 'SearchTimeOut',
    'CertificateValidation', 'CertificateFile'
}

# --- AD Import Group Task Input Definitions ---
AD_IMPORT_TASK_REQUIRED_KEYS = {'group_name'}
AD_IMPORT_TASK_OPTIONAL_KEYS = {'role', 'scope'} 

# --- OME Group Type IDs ---
STATIC_GROUP_MEMBERSHIP_TYPE_ID = 24 

# --- Default Values ---
DEFAULT_PARENT_GROUP = 'Static Groups'
DEFAULT_CREATE_FLAG = False
DEFAULT_AD_IMPORT_ROLE = "DEVICE_MANAGER"
AD_SEARCH_TYPE = "AD" 

# --- Configuration Task Input Definitions (for OME Config Manager) ---

# NTP Configuration (Input keys now directly match API payload keys)
# User: "minimally TimeZone, EnableNTP, PrimaryNTPAddress, SecondaryNTPAddress1 is required"
# SecondaryNTPAddress2 is also in example, so making it optional.
NTP_CONFIG_REQUIRED_KEYS = {'EnableNTP', 'PrimaryNTPAddress', 'TimeZone'} # Direct API keys
NTP_CONFIG_OPTIONAL_KEYS = {'SecondaryNTPAddress1', 'SecondaryNTPAddress2'} # Direct API keys

# DNS Configuration (user provides a list of servers)
DNS_SERVERS_LIST_MIN_MAX = (1, 2)

# CSR Generation Details (user-friendly keys for input, mapping happens in manager script)
CSR_DETAILS_USER_INPUT_REQUIRED_KEYS = {'common_name', 'organization', 'locality', 'state_or_province', 'country_code', 'key_size'}
CSR_DETAILS_USER_INPUT_OPTIONAL_KEYS = {'organizational_unit', 'email_address', 'subject_alternative_names_str'}
VALID_CSR_KEY_SIZES = [2048, 3072, 4096] 

# Plugin Action Task (for the list of plugin actions)
PLUGIN_ACTION_TASK_REQUIRED_KEYS = {'Id', 'Version', 'Action'}
VALID_PLUGIN_ACTIONS = ["Install", "Uninstall", "Enable", "Disable"] 


# --- OME API Endpoints ---
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
    'jobs_service_jobs': '/api/JobService/Jobs', 
    'get_job_by_id_simple': '/api/JobService/Jobs/{job_id}', 
    'update_plugins_action': '/api/PluginService/Actions/PluginService.UpdateConsolePlugins', 
    'generate_csr_action': '/api/ApplicationService/Actions/ApplicationService.GenerateCSR', 
}

# --- CLI Mappings & Config Sections ---
OME_CLI_CRED_MAP = {'ome_url': 'url', 'username': 'username', 'password': 'password'}
OME_CRED_CONFIG_SECTION = 'OME'

AD_CONFIG_SECTION = 'ActiveDirectory' 
AD_PROVIDER_FIND_CLI_MAP = {'ad_provider_name': 'Name'} 
AD_CRED_CLI_MAP = {'ad_search_username': 'UserName', 'ad_search_password': 'Password'}
AD_NAME_AND_SEARCH_CREDS_CLI_MAP = {**AD_PROVIDER_FIND_CLI_MAP, **AD_CRED_CLI_MAP}

AD_IMPORT_GROUP_CLI_ARG_NAME = 'adgroup'
AD_IMPORT_GROUP_CONFIG_SECTION = 'ADImportGroup'

STATIC_GROUP_CLI_ARG_NAME = 'StaticGroup'
STATIC_GROUP_CONFIG_SECTION = 'StaticGroups'

AD_PROVIDER_CONFIGURE_PARAMETER_CLI_ARG_NAME = 'ad_configure_parameter' 

NTP_PAYLOAD_CLI_ARG_NAME = 'ntp_payload' # CLI arg still called 'ntp_payload'
NTP_CONFIG_SECTION = 'NTPConfiguration' # Config section still 'NTPConfiguration'
                                        # This section in config.json will now expect API keys directly.

DNS_SERVERS_CLI_ARG_NAME = 'dns_servers' 
DNS_SERVERS_CONFIG_SECTION = 'DNSConfiguration' 

CSR_DETAILS_PAYLOAD_CLI_ARG_NAME = 'csr_payload' # CLI arg for user-friendly CSR details
CSR_CONFIG_SECTION = 'CSRConfiguration' # Config section for user-friendly CSR details

PLUGIN_ACTION_TASK_CLI_ARG_NAME = 'plugin_action_task' 
PLUGIN_TASKS_CONFIG_SECTION = 'PluginActionTasks' 
