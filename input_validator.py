# -*- coding: utf-8 -*-
"""Contains specific validation logic for OME automation scripts."""

# __version__ = "1.2.10" # Previous Version
__version__ = "1.2.11" # Renamed and updated NTP validator to use direct API keys.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-15 | 1.2.10  | Rahul Mehta     | Updated validate_ad_import_task_specific to use 'role' and 'scope'
#            |         |            | as optional keys, aligning with constants v1.3.9.
# 2025-05-15 | 1.2.11  | Rahul Mehta     | Renamed validate_ntp_user_input_specific to
#            |         |            | validate_ntp_config_payload_specific and updated it to validate
#            |         |            | direct API keys for NTP config, aligning with constants v1.3.10.

import logging
import constants # Expecting v1.3.10 or later
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

# ... (other validation functions from v1.2.10) ...
def validate_ome_credentials_specific(credentials_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    logger.debug(f"Validating OME credentials from {source_info}...")
    is_struct_valid, errors = validate_input(credentials_dict, constants.OME_AUTH_REQUIRED_KEYS, context_name=f"OME Credentials from {source_info}")
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(credentials_dict.get('url'), str) or not credentials_dict.get('url', '').strip():
            errors.append("'url' must be a non-empty string.")
            final_is_valid = False
        if not isinstance(credentials_dict.get('username'), str) or not credentials_dict.get('username', '').strip():
            errors.append("'username' must be a non-empty string.")
            final_is_valid = False
        if 'password' in credentials_dict and not isinstance(credentials_dict.get('password'), str):
            errors.append("'password' must be a string if provided.")
            final_is_valid = False
        elif 'password' not in credentials_dict : 
             errors.append("'password' key is required.")
             final_is_valid = False
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
            errors.append("'group_name' must be a non-empty string.")
            final_is_valid = False
        if 'devices' in group_dict and group_dict.get('devices') is not None: 
            if 'identifier_type' not in group_dict or not group_dict.get('identifier_type'):
                errors.append("'identifier_type' is required and must be non-empty if 'devices' are specified.")
                final_is_valid = False
            elif group_dict.get('identifier_type') not in constants.VALID_IDENTIFIER_TYPES:
                errors.append(f"Invalid 'identifier_type': '{group_dict.get('identifier_type')}'. Valid types: {list(constants.VALID_IDENTIFIER_TYPES)}")
                final_is_valid = False
            if not group_dict.get('devices'): 
                errors.append("'devices' list cannot be empty if the key is present and an identifier_type is specified.")
                final_is_valid = False
        if 'create' in group_dict and not isinstance(group_dict.get('create'), bool):
            errors.append("'create' must be a boolean (true/false).")
            final_is_valid = False
        if 'parent_group' in group_dict and group_dict.get('parent_group') is not None:
            if not isinstance(group_dict.get('parent_group'), str) or not str(group_dict.get('parent_group')).strip():
                errors.append("'parent_group' must be a non-empty string if provided.")
                final_is_valid = False
    return final_is_valid, errors

def validate_ad_provider_find_config_specific(ad_config_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name=f"AD Provider Find Config from {source_info}"
    logger.debug(f"Validating {context_name} (checking only Name)...")
    is_struct_valid, errors = validate_input(ad_config_dict, constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND, context_name=context_name)
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(ad_config_dict.get('Name'), str) or not str(ad_config_dict.get('Name')).strip():
            errors.append("'Name' (for AD Provider) must be a non-empty string.")
            final_is_valid = False
    return final_is_valid, errors

def validate_ad_search_credentials_specific_min(ad_creds_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"AD Search Credentials from {source_info}"
    logger.debug(f"Validating minimal {context_name}...")
    is_struct_valid, errors = validate_input(ad_creds_dict, constants.AD_CRED_REQUIRED_KEYS, context_name=context_name)
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(ad_creds_dict.get('UserName'), str) or not str(ad_creds_dict.get('UserName')).strip(): 
            errors.append("AD 'UserName' for search must be a non-empty string.")
            final_is_valid = False
        if 'Password' in ad_creds_dict and not isinstance(ad_creds_dict.get('Password'), str): 
            errors.append("AD 'Password' for search must be a string if provided.")
            final_is_valid = False
        elif 'Password' not in ad_creds_dict: 
             errors.append("AD 'Password' key is required.")
             final_is_valid = False
    return final_is_valid, errors

def validate_ad_search_credentials_and_provider_name_specific(ad_config_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"AD Search Credentials & Provider Name from {source_info}"
    logger.debug(f"Validating {context_name}...")
    required_keys = constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.union(constants.AD_CRED_REQUIRED_KEYS)
    is_struct_valid, errors = validate_input(ad_config_dict, required_keys, context_name=context_name)
    final_is_valid = is_struct_valid
    if is_struct_valid:
        if not isinstance(ad_config_dict.get('Name'), str) or not str(ad_config_dict.get('Name')).strip():
            errors.append("AD Provider 'Name' must be a non-empty string.")
            final_is_valid = False
        if not isinstance(ad_config_dict.get('UserName'), str) or not str(ad_config_dict.get('UserName')).strip(): 
            errors.append("AD 'UserName' for search must be a non-empty string.")
            final_is_valid = False
        if 'Password' in ad_config_dict and not isinstance(ad_config_dict.get('Password'), str):
            errors.append("AD 'Password' for search must be a string if provided.")
            final_is_valid = False
        elif 'Password' not in ad_config_dict:
             errors.append("AD 'Password' key is required.")
             final_is_valid = False
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
            errors.append("'group_name' value must be a non-empty string.")
            final_is_valid = False
        if 'role' in import_task_dict and import_task_dict.get('role') is not None:
            if not isinstance(import_task_dict.get('role'), str) or not str(import_task_dict.get('role')).strip():
                errors.append("'role' value must be a non-empty string if provided.")
                final_is_valid = False
        scope_key_to_check = 'scope' 
        if scope_key_to_check in import_task_dict and import_task_dict.get(scope_key_to_check) is not None:
            scope_value = import_task_dict.get(scope_key_to_check)
            if isinstance(scope_value, str):
                if not scope_value.strip():
                    errors.append(f"'{scope_key_to_check}' string value must be non-empty if provided.")
                    final_is_valid = False
            elif isinstance(scope_value, list):
                if not scope_value: 
                    errors.append(f"'{scope_key_to_check}' list must not be empty if provided as a list.")
                    final_is_valid = False
                for i, item in enumerate(scope_value):
                    if not isinstance(item, str) or not item.strip():
                        errors.append(f"'{scope_key_to_check}' list item at index {i} must be a non-empty string.")
                        final_is_valid = False
            else:
                errors.append(f"'{scope_key_to_check}' value must be a non-empty string or a list of non-empty strings if provided.")
                final_is_valid = False
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

def validate_ntp_config_payload_specific(payload_dict: Dict, source_info: str) -> Tuple[bool, List[str]]: # Renamed
    """Validates the NTP configuration payload (expects direct API keys)."""
    context_name = f"NTP Configuration Payload from {source_info}"
    logger.debug(f"Validating {context_name}...")
    # Uses constants.NTP_CONFIG_REQUIRED_KEYS and _OPTIONAL_KEYS which define direct API keys
    is_struct_valid, errors = validate_input(
        payload_dict,
        constants.NTP_CONFIG_REQUIRED_KEYS, # e.g., {'EnableNTP', 'PrimaryNTPAddress', 'TimeZone'}
        optional_keys=constants.NTP_CONFIG_OPTIONAL_KEYS, # e.g., {'SecondaryNTPAddress1', ...}
        context_name=context_name
    )
    final_is_valid = is_struct_valid

    if is_struct_valid:
        if not isinstance(payload_dict.get('EnableNTP'), bool):
            errors.append("'EnableNTP' must be a boolean.")
            final_is_valid = False
        
        # If NTP is enabled, PrimaryNTPAddress and TimeZone are effectively required by the API
        if payload_dict.get('EnableNTP') is True:
            if not isinstance(payload_dict.get('PrimaryNTPAddress'), str) or not payload_dict.get('PrimaryNTPAddress','').strip():
                errors.append("'PrimaryNTPAddress' must be a non-empty string if EnableNTP is true.")
                final_is_valid = False
            if not isinstance(payload_dict.get('TimeZone'), str) or not payload_dict.get('TimeZone','').strip():
                errors.append("'TimeZone' must be a non-empty string (OME TimeZone ID) if EnableNTP is true.")
                final_is_valid = False
        
        # Validate optional secondary servers if present
        for key in ['SecondaryNTPAddress1', 'SecondaryNTPAddress2']:
            if key in payload_dict and payload_dict.get(key) is not None: 
                if not isinstance(payload_dict.get(key), str) or not payload_dict.get(key,'').strip():
                    errors.append(f"'{key}' must be a non-empty string if provided and not null.")
                    final_is_valid = False
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

def validate_csr_user_input_specific(input_dict: Dict, source_info: str) -> Tuple[bool, List[str]]: # Validates user-friendly keys
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
                errors.append(f"Optional 'email_address' ('{email}') is not a valid format."); final_is_valid = False # Show invalid email
        if 'subject_alternative_names_str' in input_dict and input_dict.get('subject_alternative_names_str') is not None:
            if not isinstance(input_dict.get('subject_alternative_names_str'), str):
                 errors.append("Optional 'subject_alternative_names_str' must be a string."); final_is_valid = False
    return final_is_valid, errors

def validate_plugin_action_task_specific(task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"Plugin Action Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        task_dict, constants.PLUGIN_ACTION_TASK_REQUIRED_KEYS, context_name=context_name
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
    return final_is_valid, errors
def validate_plugin_action_task_specific(task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    context_name = f"Plugin Action Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        task_dict, constants.PLUGIN_ACTION_TASK_REQUIRED_KEYS, context_name=context_name
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
    return final_is_valid, errors