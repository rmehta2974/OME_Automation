# -*- coding: utf-8 -*-
"""Defines constants for OME automation scripts."""

# __version__ = "1.3.13" # Previous Version
__version__ = "1.3.14" # Added constants for Firmware, Catalog, and Baseline management.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-19 | 1.3.13  | Gemini     | Added 'get_plugin_available_versions' API endpoint.
# 2025-05-19 | 1.3.14  | Gemini     | Added constants for catalog, baseline, firmware update features,
#            |         |            | adapting from update_firmware_using_catalog.py.

import logging
logger = logging.getLogger(__name__)

# --- Input Definitions ---
OME_AUTH_REQUIRED_KEYS = {'url', 'username', 'password'}
STATIC_GROUP_REQUIRED_KEYS = {'group_name'} 
STATIC_GROUP_OPTIONAL_KEYS = {'description', 'devices', 'parent_group', 'create', 'identifier_type'} 
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
DEFAULT_CREATE_FLAG = True 
DEFAULT_AD_IMPORT_ROLE = "DEVICE_MANAGER"
AD_SEARCH_TYPE = "AD" 
DEFAULT_MAX_JOB_RETRIES = 20 # For polling jobs
DEFAULT_JOB_RETRY_INTERVAL = 30 # seconds, for polling jobs

# --- Configuration Task Input Definitions (for OME Config Manager) ---
NTP_CONFIG_REQUIRED_KEYS = {'EnableNTP', 'PrimaryNTPAddress', 'TimeZone'} 
NTP_CONFIG_OPTIONAL_KEYS = {'SecondaryNTPAddress1', 'SecondaryNTPAddress2'} 
DNS_SERVERS_LIST_MIN_MAX = (1, 2)
CSR_DETAILS_USER_INPUT_REQUIRED_KEYS = {'common_name', 'organization', 'locality', 'state_or_province', 'country_code', 'key_size'}
CSR_DETAILS_USER_INPUT_OPTIONAL_KEYS = {'organizational_unit', 'email_address', 'subject_alternative_names_str'}
VALID_CSR_KEY_SIZES = [2048, 3072, 4096] 
PLUGIN_ACTION_TASK_REQUIRED_KEYS = {'Id', 'Version', 'Action'}
PLUGIN_ACTION_TASK_OPTIONAL_KEYS = {'AcceptAllLicenseAgreements'}
VALID_PLUGIN_ACTIONS = ["Install", "Uninstall", "Enable", "Disable", "Update"] 
PLUGIN_COMPATIBILITY_CHECK_PAYLOAD_KEYS = {'OmeVersion', 'Plugins'} 

# --- NEW: Catalog, Baseline, Firmware Update Input Definitions ---
# Catalog Creation Task (user input keys)
CATALOG_CREATION_BASE_REQUIRED_KEYS = {'repo_type'} # e.g., "DELL_ONLINE", "CIFS", "NFS", "HTTP", "HTTPS", "LOCAL"
CATALOG_REPO_TYPES = ['DELL_ONLINE', 'NFS', 'CIFS', 'HTTP', 'HTTPS', 'LOCAL'] # Valid repo_type values
CATALOG_CREATION_DELL_ONLINE_OPTIONAL_KEYS = {'catalog_name_prefix'} # For naming the Dell Online catalog repo
CATALOG_CREATION_NETWORK_SHARES_REQUIRED_KEYS = {'repo_source_ip', 'catalog_path'} # For NFS, CIFS, HTTP, HTTPS
CATALOG_CREATION_CIFS_SPECIFIC_REQUIRED_KEYS = {'repo_user', 'repo_password'}
CATALOG_CREATION_CIFS_SPECIFIC_OPTIONAL_KEYS = {'repo_domain'}
CATALOG_CREATION_LOCAL_SPECIFIC_REQUIRED_KEYS = {'catalog_path'} # Full path on appliance for LOCAL type

# Baseline Creation Task (user input keys)
BASELINE_CREATION_REQUIRED_KEYS = {'baseline_name', 'catalog_name_or_id'} # User provides catalog name or ID
BASELINE_CREATION_OPTIONAL_KEYS = {
    'description', 'target_group_names', 'target_device_ids', 
    'target_service_tags', 'target_idrac_ips', 'target_device_names',
    'downgrade_enabled', 'is_64bit' # is_64bit might be deprecated or auto-detected by OME
}
# Target specification (one of these groups of keys)
BASELINE_TARGETS_GROUP_KEYS = {'target_group_names'} # List of group names
BASELINE_TARGETS_DEVICE_ID_KEYS = {'target_device_ids'} # List of OME Device IDs
BASELINE_TARGETS_SERVICE_TAG_KEYS = {'target_service_tags'} # List of service tags
BASELINE_TARGETS_IDRAC_IP_KEYS = {'target_idrac_ips'} # List of iDRAC IPs
BASELINE_TARGETS_DEVICE_NAME_KEYS = {'target_device_names'} # List of device names

# Firmware Update Job Task (user input keys)
FIRMWARE_UPDATE_TASK_REQUIRED_KEYS = {'baseline_name_or_id'} # Baseline to use for the update
FIRMWARE_UPDATE_TASK_OPTIONAL_KEYS = {
    'update_actions', # String or List: "UPGRADE", "DOWNGRADE", or "flash-all" (translates to both)
    'stage_update', # Boolean: true to stage, false to apply now (default false)
    'reboot_needed_action', # String: e.g., "StageAndReboot", "StageOnly", "RebootNow" - OME specific values
    'job_name_prefix', # For naming the firmware update job
    'job_description'  # Description for the firmware update job
}
VALID_FIRMWARE_UPDATE_ACTIONS = ["UPGRADE", "DOWNGRADE"] # "FLASH-ALL" is a meta-action

# --- OME API Endpoints ---
API_ENDPOINTS = {
    'auth': '/api/SessionService/Sessions',
    'devices': '/api/DeviceService/Devices',
    'device_types': '/api/DeviceService/DeviceType', # From update_firmware_using_catalog.py
    'groups': '/api/GroupService/Groups',
    'group_devices': '/api/GroupService/Groups({group_id})/Devices', # Was AllLeafDevices, Devices is more common
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
    'jobs_service_jobs': '/api/JobService/Jobs', # Base for jobs, POST to create firmware update job
    'get_job_by_id_simple': '/api/JobService/Jobs/{job_id}', 
    'job_execution_histories': '/api/JobService/Jobs({job_id})/ExecutionHistories', # From update_firmware_using_catalog.py
    'job_execution_history_details': '/api/JobService/Jobs({job_id})/ExecutionHistories({history_id})/ExecutionHistoryDetails', # From update_firmware_using_catalog.py
    'run_jobs_action': '/api/JobService/Actions/JobService.RunJobs', # From update_firmware_using_catalog.py (for rerun baseline)
    'job_types': '/api/JobService/JobTypes', # From update_firmware_using_catalog.py (to get "Update_Task" ID)
    'update_plugins_action': '/api/PluginService/Actions/PluginService.UpdateConsolePlugins', 
    'generate_csr_action': '/api/ApplicationService/Actions/ApplicationService.GenerateCSR',
    'get_plugins': '/api/PluginService/Plugins', 
    'check_plugin_compatibility': '/api/PluginService/Actions/PluginService.CheckPluginCompatibility',
    'appliance_information': '/api/ApplicationService/application',
    'get_plugin_available_versions': "/api/PluginService/Plugins('{plugin_id}')/AvailableVersionDetails",

    # NEW Endpoints for Firmware/Catalog/Baseline from update_firmware_using_catalog.py
    'catalogs': '/api/UpdateService/Catalogs', # GET all, POST new
    'catalog_by_id': '/api/UpdateService/Catalogs({catalog_id})', # GET specific catalog
    'refresh_catalogs_action': '/api/UpdateService/Actions/UpdateService.RefreshCatalogs', # POST to refresh
    'baselines': '/api/UpdateService/Baselines', # GET all, POST new
    'baseline_by_id': '/api/UpdateService/Baselines({baseline_id})', # GET specific baseline
    'baseline_device_compliance_reports': '/api/UpdateService/Baselines({baseline_id})/DeviceComplianceReports', # GET compliance
    # Firmware update job is created via POST to /api/JobService/Jobs
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

NTP_PAYLOAD_CLI_ARG_NAME = 'ntp_payload' 
NTP_CONFIG_SECTION = 'NTPConfiguration' 

DNS_SERVERS_CLI_ARG_NAME = 'dns_servers' 
DNS_SERVERS_CONFIG_SECTION = 'DNSConfiguration' 

CSR_DETAILS_PAYLOAD_CLI_ARG_NAME = 'csr_payload' 
CSR_CONFIG_SECTION = 'CSRConfiguration' 

PLUGIN_ACTION_TASK_CLI_ARG_NAME = 'plugin_action_task' 
PLUGIN_TASKS_CONFIG_SECTION = 'PluginActionTasks' 

# --- NEW: CLI Argument Names and Config Section Names for Firmware Update Workflow ---
# Catalog Management
CATALOG_TASK_CLI_ARG_NAME = 'catalog_task' 
CATALOG_CONFIG_SECTION = 'CatalogConfiguration' # Holds one catalog definition object for creation
CATALOG_NAME_CLI_ARG_NAME = 'catalog_name' # For specifying an existing catalog by name to use/refresh
CATALOG_REFRESH_FLAG_CLI_ARG_NAME = 'refresh_catalog' # Boolean flag for --catalog-name

# Baseline Management
BASELINE_TASK_CLI_ARG_NAME = 'baseline_task' 
BASELINE_CONFIG_SECTION = 'BaselineConfiguration' # Holds one baseline definition object for creation
BASELINE_NAME_CLI_ARG_NAME = 'baseline_name' # For specifying an existing baseline by name

# Firmware Update Job
FIRMWARE_UPDATE_TASK_CLI_ARG_NAME = 'firmware_update_task' 
FIRMWARE_UPDATE_CONFIG_SECTION = 'FirmwareUpdateConfiguration' # Holds parameters for the update job itself
# Target device specifiers for firmware updates (can also be in baseline task)
FW_TARGET_GROUPNAME_CLI_ARG = 'fw_target_groupname'
FW_TARGET_SERVICETAGS_CLI_ARG = 'fw_target_servicetags' 
FW_TARGET_IDRACIPS_CLI_ARG = 'fw_target_idracips'     
FW_TARGET_DEVICENAMES_CLI_ARG = 'fw_target_devicenames' 
FW_TARGET_DEVICEIDS_CLI_ARG = 'fw_target_deviceids'     
