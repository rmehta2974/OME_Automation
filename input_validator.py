# -*- coding: utf-8 -*-
"""Contains specific validation logic for OME automation scripts."""

# __version__ = "1.2.13" # Previous Version
__version__ = "1.2.14" # Added AcceptAllLicenseAgreements validation to plugin tasks.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-19 | 1.2.13  | Rahul Mehta     | Added validators for Catalog, Baseline, and Firmware Update tasks.
# 2025-05-19 | 1.2.14  | Rahul Mehta     | Updated validate_plugin_action_task_specific to include
#            |         |            | optional 'AcceptAllLicenseAgreements' boolean key.

import logging
import constants # Expecting v1.3.15 or later
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

def validate_input(data: Dict, required_keys: set, optional_keys: Optional[set] = None, context_name: str = "Input") -> Tuple[bool, List[str]]:
    errors = []
    is_valid = True 
    if not isinstance(data, dict):
        errors.append(f"Input data for '{context_name}' is not a dictionary (type: {type(data)}).")
        return False, errors 
    missing_keys = required_keys - set(data.keys())
    if missing_keys:
        errors.append(f"Missing required key(s) for '{context_name}': {', '.join(sorted(list(missing_keys)))}")
        is_valid = False 
    return is_valid, errors

# ... (Other validation functions from v1.2.13 remain the same) ...
def validate_ome_credentials_specific(credentials_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    logger.debug(f"Validating OME credentials from {source_info}...")
    is_struct_valid, errors = validate_input(credentials_dict, constants.OME_AUTH_REQUIRED_KEYS, context_name=f"OME Credentials from {source_info}")
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(credentials_dict.get('url'), str) or not credentials_dict.get('url', '').strip():
            errors.append("'url' must be a non-empty string."); final_is_valid = False
        if not isinstance(credentials_dict.get('username'), str) or not credentials_dict.get('username', '').strip():
            errors.append("'username' must be a non-empty string."); final_is_valid = False
        if 'password' in credentials_dict and not isinstance(credentials_dict.get('password'), str):
            errors.append("'password' must be a string if provided."); final_is_valid = False
        elif 'password' not in credentials_dict : 
             errors.append("'password' key is required."); final_is_valid = False
    return final_is_valid, errors

def validate_static_group_definition_specific(group_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    logger.debug(f"Validating static group definition from {source_info}...")
    is_struct_valid, errors = validate_input(
        group_dict, constants.STATIC_GROUP_REQUIRED_KEYS,
        optional_keys=constants.STATIC_GROUP_OPTIONAL_KEYS, context_name=f"Static Group from {source_info}"
    )
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(group_dict.get('group_name'), str) or not str(group_dict.get('group_name')).strip():
            errors.append("'group_name' must be a non-empty string."); final_is_valid = False
        if 'description' in group_dict and group_dict.get('description') is not None and \
           (not isinstance(group_dict.get('description'), str)): 
             errors.append("'description' must be a string if provided."); final_is_valid = False
        if 'devices' in group_dict and group_dict.get('devices') is not None: 
            if 'identifier_type' not in group_dict or not group_dict.get('identifier_type'):
                errors.append("'identifier_type' is required if 'devices' are specified."); final_is_valid = False
            elif group_dict.get('identifier_type') not in constants.VALID_IDENTIFIER_TYPES:
                errors.append(f"Invalid 'identifier_type'. Valid: {list(constants.VALID_IDENTIFIER_TYPES)}"); final_is_valid = False
            if not group_dict.get('devices'): 
                errors.append("'devices' list/string cannot be empty if key is present and identifier_type specified."); final_is_valid = False
        if 'create' in group_dict and not isinstance(group_dict.get('create'), bool):
            errors.append("'create' must be a boolean."); final_is_valid = False
        if 'parent_group' in group_dict and group_dict.get('parent_group') is not None:
            if not isinstance(group_dict.get('parent_group'), str) or not str(group_dict.get('parent_group')).strip():
                errors.append("'parent_group' must be a non-empty string if provided."); final_is_valid = False
    return final_is_valid, errors

def validate_ad_provider_find_config_specific(ad_config_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name=f"AD Provider Find Config from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(ad_config_dict, constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND, context_name=context_name)
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(ad_config_dict.get('Name'), str) or not str(ad_config_dict.get('Name')).strip():
            errors.append("'Name' (for AD Provider) must be a non-empty string."); final_is_valid = False
    return final_is_valid, errors

def validate_ad_search_credentials_specific_min(ad_creds_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"AD Search Credentials from {source_info}"
    logger.debug(f"Validating minimal {context_name}...")
    is_struct_valid, errors = validate_input(ad_creds_dict, constants.AD_CRED_REQUIRED_KEYS, context_name=context_name)
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(ad_creds_dict.get('UserName'), str) or not str(ad_creds_dict.get('UserName')).strip(): 
            errors.append("AD 'UserName' for search must be a non-empty string."); final_is_valid = False
        if 'Password' in ad_creds_dict and not isinstance(ad_creds_dict.get('Password'), str): 
            errors.append("AD 'Password' for search must be a string if provided."); final_is_valid = False
        elif 'Password' not in ad_creds_dict: 
             errors.append("AD 'Password' key is required."); final_is_valid = False
    return final_is_valid, errors

def validate_ad_search_credentials_and_provider_name_specific(ad_config_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"AD Search Credentials & Provider Name from {source_info}"
    logger.debug(f"Validating {context_name}...")
    required_keys = constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.union(constants.AD_CRED_REQUIRED_KEYS)
    is_struct_valid, errors = validate_input(ad_config_dict, required_keys, context_name=context_name)
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(ad_config_dict.get('Name'), str) or not str(ad_config_dict.get('Name')).strip():
            errors.append("AD Provider 'Name' must be a non-empty string."); final_is_valid = False
        if not isinstance(ad_config_dict.get('UserName'), str) or not str(ad_config_dict.get('UserName')).strip(): 
            errors.append("AD 'UserName' for search must be a non-empty string."); final_is_valid = False
        if 'Password' in ad_config_dict and not isinstance(ad_config_dict.get('Password'), str):
            errors.append("AD 'Password' for search must be a string if provided."); final_is_valid = False
        elif 'Password' not in ad_config_dict:
             errors.append("AD 'Password' key is required."); final_is_valid = False
    return final_is_valid, errors

def validate_ad_import_task_specific(import_task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"AD Import Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        import_task_dict, constants.AD_IMPORT_TASK_REQUIRED_KEYS,
        optional_keys=constants.AD_IMPORT_TASK_OPTIONAL_KEYS, context_name=context_name
    )
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(import_task_dict.get('group_name'), str) or not str(import_task_dict.get('group_name')).strip():
            errors.append("'group_name' value must be a non-empty string."); final_is_valid = False
        if 'role' in import_task_dict and import_task_dict.get('role') is not None:
            if not isinstance(import_task_dict.get('role'), str) or not str(import_task_dict.get('role')).strip():
                errors.append("'role' value must be a non-empty string if provided."); final_is_valid = False
        scope_key_to_check = 'scope' 
        if scope_key_to_check in import_task_dict and import_task_dict.get(scope_key_to_check) is not None:
            scope_value = import_task_dict.get(scope_key_to_check)
            if isinstance(scope_value, str):
                if not scope_value.strip():
                    errors.append(f"'{scope_key_to_check}' string value must be non-empty if provided."); final_is_valid = False
            elif isinstance(scope_value, list):
                if not scope_value: 
                    errors.append(f"'{scope_key_to_check}' list must not be empty if provided as a list."); final_is_valid = False
                for i, item in enumerate(scope_value):
                    if not isinstance(item, str) or not item.strip():
                        errors.append(f"'{scope_key_to_check}' list item at index {i} must be a non-empty string."); final_is_valid = False
            else:
                errors.append(f"'{scope_key_to_check}' value must be a non-empty string or a list of non-empty strings if provided."); final_is_valid = False
    return final_is_valid, errors

def validate_ad_provider_payload_specific(payload_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"AD Provider Configuration Payload from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        payload_dict, constants.AD_PROVIDER_PAYLOAD_REQUIRED_KEYS, 
        optional_keys=constants.AD_PROVIDER_PAYLOAD_OPTIONAL_KEYS, context_name=context_name
    )
    final_is_valid = is_struct_valid
    if is_struct_valid: 
        for key in constants.AD_PROVIDER_PAYLOAD_REQUIRED_KEYS:
            value = payload_dict.get(key)
            if key == 'Name' and (not isinstance(value, str) or not value.strip()):
                errors.append("'Name' must be a non-empty string."); final_is_valid = False
            elif key == 'ServerType' and value != "MANUAL":
                 errors.append("'ServerType' must be 'MANUAL'."); final_is_valid = False
            elif key == 'ServerName' and (not isinstance(value, list) or not value or not all(isinstance(s, str) and s.strip() for s in value)):
                errors.append("'ServerName' must be a non-empty list of non-empty strings."); final_is_valid = False
            elif key == 'UserName' and not isinstance(value, str): 
                errors.append("'UserName' (bind) must be a string."); final_is_valid = False
            elif key == 'Password' and not isinstance(value, str): 
                errors.append("'Password' (bind) must be a string."); final_is_valid = False
            elif key == 'ServerPort' and (not isinstance(value, int) or not (0 < value < 65536)):
                errors.append("'ServerPort' must be a valid integer (1-65535)."); final_is_valid = False
            elif key == 'NetworkTimeOut' and (not isinstance(value, int) or value <= 0):
                errors.append("'NetworkTimeOut' must be a positive integer."); final_is_valid = False
            elif key == 'SearchTimeOut' and (not isinstance(value, int) or value <= 0):
                errors.append("'SearchTimeOut' must be a positive integer."); final_is_valid = False
            elif key == 'GroupDomain' and not isinstance(value, str): 
                errors.append("'GroupDomain' must be a string."); final_is_valid = False
        if 'CertificateValidation' in payload_dict and not isinstance(payload_dict.get('CertificateValidation'), bool):
            errors.append("'CertificateValidation' must be a boolean if provided."); final_is_valid = False
        if 'CertificateFile' in payload_dict and not isinstance(payload_dict.get('CertificateFile'), str):
            errors.append("'CertificateFile' must be a string if provided."); final_is_valid = False
    return final_is_valid, errors

def validate_ad_test_connection_payload_specific(payload_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"AD Test Connection Payload from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        payload_dict, constants.AD_TEST_CONNECTION_PAYLOAD_REQUIRED_KEYS,
        optional_keys=None, context_name=context_name
    )
    final_is_valid = is_struct_valid
    if is_struct_valid:
        for key in constants.AD_TEST_CONNECTION_PAYLOAD_REQUIRED_KEYS:
            value = payload_dict.get(key)
            if key == 'Name' and (not isinstance(value, str) or not value.strip()):
                errors.append(f"Test payload '{key}' must be a non-empty string."); final_is_valid = False
            elif key == 'ServerType' and value != "MANUAL":
                 errors.append(f"Test payload '{key}' must be 'MANUAL'."); final_is_valid = False
            elif key == 'ServerName' and (not isinstance(value, list) or not value or not all(isinstance(s, str) and s.strip() for s in value)):
                errors.append(f"Test payload '{key}' must be a non-empty list of non-empty strings."); final_is_valid = False
            elif key == 'UserName' and (not isinstance(value, str) or not value.strip()): 
                errors.append(f"Test payload '{key}' (search user) must be a non-empty string."); final_is_valid = False
            elif key == 'Password' and not isinstance(value, str): 
                errors.append(f"Test payload '{key}' (search password) must be a string."); final_is_valid = False
            elif key == 'ServerPort' and (not isinstance(value, int) or not (0 < value < 65536)):
                errors.append(f"Test payload '{key}' must be a valid integer (1-65535)."); final_is_valid = False
            elif key == 'NetworkTimeOut' and (not isinstance(value, int) or value <= 0):
                errors.append(f"Test payload '{key}' must be a positive integer."); final_is_valid = False
            elif key == 'SearchTimeOut' and (not isinstance(value, int) or value <= 0):
                errors.append(f"Test payload '{key}' must be a positive integer."); final_is_valid = False
            elif key == 'CertificateValidation' and not isinstance(value, bool):
                errors.append(f"Test payload '{key}' must be a boolean."); final_is_valid = False
            elif key == 'CertificateFile' and not isinstance(value, str): 
                errors.append(f"Test payload '{key}' must be a string."); final_is_valid = False
    return final_is_valid, errors

def validate_ntp_config_payload_specific(payload_dict: Dict, source_info: str) -> Tuple[bool, List[str]]: 
    context_name = f"NTP Configuration Payload from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        payload_dict, constants.NTP_CONFIG_REQUIRED_KEYS, 
        optional_keys=constants.NTP_CONFIG_OPTIONAL_KEYS, context_name=context_name
    )
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(payload_dict.get('EnableNTP'), bool):
            errors.append("'EnableNTP' must be a boolean."); final_is_valid = False
        if payload_dict.get('EnableNTP') is True:
            if not isinstance(payload_dict.get('PrimaryNTPAddress'), str) or not payload_dict.get('PrimaryNTPAddress','').strip():
                errors.append("'PrimaryNTPAddress' must be a non-empty string if EnableNTP is true."); final_is_valid = False
            if not isinstance(payload_dict.get('TimeZone'), str) or not payload_dict.get('TimeZone','').strip():
                errors.append("'TimeZone' must be a non-empty string (OME TimeZone ID) if EnableNTP is true."); final_is_valid = False
        for key in ['SecondaryNTPAddress1', 'SecondaryNTPAddress2']:
            if key in payload_dict and payload_dict.get(key) is not None: 
                if not isinstance(payload_dict.get(key), str) or not payload_dict.get(key,'').strip(): 
                    errors.append(f"'{key}' must be a non-empty string if provided and not null."); final_is_valid = False
    return final_is_valid, errors

def validate_dns_servers_list_specific(servers_list: List[Any], source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"DNS Server List from {source_info}"
    logger.debug(f"Validating {context_name}...")
    errors = []
    is_valid = True
    if not isinstance(servers_list, list):
        errors.append("DNS servers input must be a list."); return False, errors
    min_dns, max_dns = constants.DNS_SERVERS_LIST_MIN_MAX
    if not (min_dns <= len(servers_list) <= max_dns):
        errors.append(f"Number of DNS servers must be between {min_dns} and {max_dns}. Found: {len(servers_list)}."); is_valid = False
    for i, server in enumerate(servers_list):
        if not isinstance(server, str) or not server.strip():
            errors.append(f"DNS server at index {i} must be a non-empty string."); is_valid = False
    return is_valid, errors

def validate_csr_user_input_specific(input_dict: Dict, source_info: str) -> Tuple[bool, List[str]]: 
    context_name = f"CSR User Input from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        input_dict, constants.CSR_DETAILS_USER_INPUT_REQUIRED_KEYS, 
        optional_keys=constants.CSR_DETAILS_USER_INPUT_OPTIONAL_KEYS, context_name=context_name
    )
    final_is_valid = is_struct_valid
    if is_struct_valid:
        for key in constants.CSR_DETAILS_USER_INPUT_REQUIRED_KEYS:
            value = input_dict.get(key)
            if key == 'key_size':
                if not ((isinstance(value, int) and value in constants.VALID_CSR_KEY_SIZES) or \
                        (isinstance(value, str) and value.isdigit() and int(value) in constants.VALID_CSR_KEY_SIZES)):
                    errors.append(f"'{key}' ('{value}') is invalid. Must be one of {constants.VALID_CSR_KEY_SIZES}."); final_is_valid = False
            elif not isinstance(value, str) or not value.strip():
                errors.append(f"Required CSR field '{key}' must be a non-empty string."); final_is_valid = False
        if 'country_code' in input_dict and (not isinstance(input_dict['country_code'], str) or len(input_dict['country_code']) != 2):
            errors.append("'country_code' must be a 2-letter string."); final_is_valid = False
        if 'email_address' in input_dict and input_dict.get('email_address') is not None:
            email = input_dict.get('email_address','')
            if not isinstance(email, str) or ('@' not in email or '.' not in email): 
                errors.append(f"Optional 'email_address' ('{email}') is not a valid format."); final_is_valid = False 
        if 'subject_alternative_names_str' in input_dict and input_dict.get('subject_alternative_names_str') is not None:
            if not isinstance(input_dict.get('subject_alternative_names_str'), str):
                 errors.append("Optional 'subject_alternative_names_str' must be a string."); final_is_valid = False
    return final_is_valid, errors

def validate_plugin_action_task_specific(task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Validates a single plugin action task."""
    context_name = f"Plugin Action Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    # Now includes 'AcceptAllLicenseAgreements' as an optional key
    is_struct_valid, errors = validate_input(
        task_dict,
        constants.PLUGIN_ACTION_TASK_REQUIRED_KEYS,
        optional_keys=constants.PLUGIN_ACTION_TASK_OPTIONAL_KEYS, # This now includes 'AcceptAllLicenseAgreements'
        context_name=context_name
    )
    final_is_valid = is_struct_valid

    if is_struct_valid:
        if not isinstance(task_dict.get('Id'), str) or not task_dict.get('Id','').strip():
            errors.append("'Id' (plugin GUID) must be a non-empty string."); final_is_valid = False
        if not isinstance(task_dict.get('Version'), str) or not task_dict.get('Version','').strip():
            errors.append("'Version' must be a non-empty string."); final_is_valid = False
        action = task_dict.get('Action')
        if not isinstance(action, str) or action not in constants.VALID_PLUGIN_ACTIONS:
            errors.append(f"'Action' ('{action}') is invalid. Must be one of {constants.VALID_PLUGIN_ACTIONS}."); final_is_valid = False
        
        # Validate AcceptAllLicenseAgreements if present
        if 'AcceptAllLicenseAgreements' in task_dict and \
           not isinstance(task_dict.get('AcceptAllLicenseAgreements'), bool):
            errors.append("'AcceptAllLicenseAgreements' must be a boolean if provided."); final_is_valid = False
            
    return final_is_valid, errors

# --- NEW Validators for Firmware Update Workflow ---
def validate_catalog_creation_task_specific(task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"Catalog Creation Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(task_dict, constants.CATALOG_CREATION_BASE_REQUIRED_KEYS, context_name=context_name)
    final_is_valid = is_struct_valid
    if is_struct_valid:
        repo_type = task_dict.get('repo_type')
        if not isinstance(repo_type, str) or repo_type.upper() not in constants.CATALOG_REPO_TYPES:
            errors.append(f"Invalid 'repo_type'. Must be one of {constants.CATALOG_REPO_TYPES}."); final_is_valid = False
        else:
            repo_type = repo_type.upper() # Normalize for checks
            if repo_type in ['NFS', 'CIFS', 'HTTP', 'HTTPS']:
                missing_network_keys = constants.CATALOG_CREATION_NETWORK_SHARES_REQUIRED_KEYS - set(task_dict.keys())
                if missing_network_keys: errors.append(f"Missing keys for '{repo_type}': {missing_network_keys}"); final_is_valid = False
                else:
                    if not isinstance(task_dict.get('repo_source_ip'), str) or not task_dict.get('repo_source_ip','').strip():
                        errors.append("'repo_source_ip' must be non-empty string."); final_is_valid = False
                    if not isinstance(task_dict.get('catalog_path'), str) or not task_dict.get('catalog_path','').strip():
                        errors.append("'catalog_path' must be non-empty string."); final_is_valid = False
            if repo_type == 'LOCAL':
                if not isinstance(task_dict.get('catalog_path'), str) or not task_dict.get('catalog_path','').strip():
                     errors.append("'catalog_path' must be non-empty string for LOCAL repo_type."); final_is_valid = False
            if repo_type == 'CIFS':
                missing_cifs_keys = constants.CATALOG_CREATION_CIFS_SPECIFIC_REQUIRED_KEYS - set(task_dict.keys())
                if missing_cifs_keys: errors.append(f"Missing CIFS keys: {missing_cifs_keys}"); final_is_valid = False
                else:
                    if not isinstance(task_dict.get('repo_user'), str) or not task_dict.get('repo_user','').strip():
                        errors.append("'repo_user' must be non-empty string for CIFS."); final_is_valid = False
                    if not isinstance(task_dict.get('repo_password'), str): # Password can be empty
                        errors.append("'repo_password' must be string for CIFS."); final_is_valid = False
                    if 'repo_domain' in task_dict and task_dict.get('repo_domain') is not None and not isinstance(task_dict.get('repo_domain'), str):
                         errors.append("'repo_domain' must be string if provided for CIFS."); final_is_valid = False
            if repo_type == 'DELL_ONLINE' and 'catalog_name_prefix' in task_dict:
                if not isinstance(task_dict.get('catalog_name_prefix'), str) or not task_dict.get('catalog_name_prefix','').strip():
                    errors.append("'catalog_name_prefix' must be non-empty string if provided for DELL_ONLINE."); final_is_valid = False
    return final_is_valid, errors

def validate_baseline_creation_task_specific(task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"Baseline Creation Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        task_dict, constants.BASELINE_CREATION_REQUIRED_KEYS,
        optional_keys=constants.BASELINE_CREATION_OPTIONAL_KEYS, context_name=context_name
    )
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(task_dict.get('baseline_name'), str) or not task_dict.get('baseline_name','').strip():
            errors.append("'baseline_name' must be non-empty string."); final_is_valid = False
        cat_ref = task_dict.get('catalog_name_or_id')
        if not isinstance(cat_ref, (str, int)) or (isinstance(cat_ref, str) and not cat_ref.strip()):
            errors.append("'catalog_name_or_id' must be non-empty string or int ID."); final_is_valid = False
        target_keys_present = [key for key in [
            'target_group_names', 'target_device_ids', 'target_service_tags', 
            'target_idrac_ips', 'target_device_names'
        ] if key in task_dict and task_dict.get(key)]
        if not target_keys_present:
            errors.append("At least one target specifier required (e.g., 'target_group_names')."); final_is_valid = False
        else:
            for key in target_keys_present:
                value = task_dict.get(key)
                if not isinstance(value, list) or not value or \
                   not all(isinstance(item, (str, int)) and (str(item).strip() if isinstance(item, str) else True) for item in value):
                    errors.append(f"'{key}' must be non-empty list of non-empty strings/integers."); final_is_valid = False
        if 'downgrade_enabled' in task_dict and not isinstance(task_dict.get('downgrade_enabled'), bool):
            errors.append("'downgrade_enabled' must be boolean."); final_is_valid = False
        if 'is_64bit' in task_dict and not isinstance(task_dict.get('is_64bit'), bool):
            errors.append("'is_64bit' must be boolean."); final_is_valid = False
    return final_is_valid, errors

def validate_firmware_update_task_specific(task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"Firmware Update Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        task_dict, constants.FIRMWARE_UPDATE_TASK_REQUIRED_KEYS,
        optional_keys=constants.FIRMWARE_UPDATE_TASK_OPTIONAL_KEYS, context_name=context_name
    )
    final_is_valid = is_struct_valid
    if is_struct_valid:
        bl_ref = task_dict.get('baseline_name_or_id')
        if not isinstance(bl_ref, (str, int)) or (isinstance(bl_ref, str) and not bl_ref.strip()):
            errors.append("'baseline_name_or_id' must be non-empty string or int ID."); final_is_valid = False
        if 'update_actions' in task_dict and task_dict.get('update_actions') is not None:
            actions = task_dict.get('update_actions')
            valid_actions_upper = [act.upper() for act in constants.VALID_FIRMWARE_UPDATE_ACTIONS]
            if isinstance(actions, str):
                if actions.upper() not in valid_actions_upper and actions.lower() != "flash-all":
                    errors.append(f"Invalid 'update_actions' string. Valid: {valid_actions_upper} or 'flash-all'."); final_is_valid = False
            elif isinstance(actions, list):
                if not actions or not all(isinstance(a, str) and a.upper() in valid_actions_upper for a in actions):
                    errors.append(f"Invalid 'update_actions' list. Items must be one of {valid_actions_upper}."); final_is_valid = False
            else: errors.append("'update_actions' must be string or list."); final_is_valid = False
        if 'stage_update' in task_dict and not isinstance(task_dict.get('stage_update'), bool):
            errors.append("'stage_update' must be boolean."); final_is_valid = False
        if 'reboot_needed_action' in task_dict and not isinstance(task_dict.get('reboot_needed_action'), str):
             errors.append("'reboot_needed_action' must be a string if provided."); final_is_valid = False
    return final_is_valid, errors

