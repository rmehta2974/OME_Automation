# -*- coding: utf-8 -*-
"""Contains specific validation logic for OME automation scripts."""

# __version__ = "1.2.3" # Previous consolidations
__version__ = "1.2.4" # Added validation functions for OME Configuration Manager features.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history from 1.2.3)
# 2025-05-15 | 1.2.4   | Rahul Mehta   | Added new validation functions for AD Provider payload, NTP,
#            |         |            | DNS, CSR, Plugins, and a minimal AD search creds validator.

import logging
import constants # Expecting v1.3.2 or later
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

def validate_input(data: Dict, required_keys: set, optional_keys: Optional[set] = None, context_name: str = "Input") -> Tuple[bool, List[str]]:
    """Generic input dictionary validator for required and optional keys."""
    errors = []
    is_valid = True # Assume valid initially for this specific check
    if not isinstance(data, dict):
        errors.append(f"Input data for '{context_name}' is not a dictionary (type: {type(data)}).")
        return False, errors # Hard fail if not a dict

    # Check for required keys
    missing_keys = required_keys - set(data.keys())
    if missing_keys:
        errors.append(f"Missing required key(s): {', '.join(sorted(list(missing_keys)))}")
        is_valid = False # Mark as invalid if keys are missing

    # Check for unknown keys (optional)
    # known_keys = required_keys.union(optional_keys if optional_keys else set())
    # unknown_keys = set(data.keys()) - known_keys
    # if unknown_keys:
    #     errors.append(f"Unknown key(s) provided: {', '.join(sorted(list(unknown_keys)))}")
    # is_valid = False # Decide if unknown keys make it invalid

    return is_valid, errors

def validate_ome_credentials_specific(credentials_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Validates OME connection credentials."""
    logger.debug(f"Validating OME credentials from {source_info}...")
    is_struct_valid, errors = validate_input(credentials_dict, constants.OME_AUTH_REQUIRED_KEYS, context_name=f"OME Credentials from {source_info}")
    
    final_is_valid = is_struct_valid # Start with structural validity

    if is_struct_valid: # Only proceed with content checks if structure is okay
        if not isinstance(credentials_dict.get('url'), str) or not credentials_dict.get('url', '').strip():
            errors.append("'url' must be a non-empty string.")
            final_is_valid = False
        if not isinstance(credentials_dict.get('username'), str) or not credentials_dict.get('username', '').strip():
            errors.append("'username' must be a non-empty string.")
            final_is_valid = False
        # Password can be an empty string, but must be a string type
        if 'password' in credentials_dict and not isinstance(credentials_dict.get('password'), str):
            errors.append("'password' must be a string if provided.") # Or make it required and non-empty too
            final_is_valid = False
        elif 'password' not in credentials_dict : # If password is truly required by OME_AUTH_REQUIRED_KEYS
             errors.append("'password' key is required.") # This should be caught by validate_input if in required_keys
             final_is_valid = False


    return final_is_valid, errors

def validate_static_group_definition_specific(group_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Validates a comprehensive static group definition (used by sg_group.py and ome_config_manager.py)."""
    logger.debug(f"Validating static group definition from {source_info}...")
    is_struct_valid, errors = validate_input(
        group_dict,
        constants.STATIC_GROUP_REQUIRED_KEYS,
        optional_keys=constants.STATIC_GROUP_OPTIONAL_KEYS,
        context_name=f"Static Group from {source_info}"
    )
    final_is_valid = is_struct_valid

    if is_struct_valid:
        if not isinstance(group_dict.get('group_name'), str) or not str(group_dict.get('group_name')).strip():
            errors.append("'group_name' must be a non-empty string.")
            final_is_valid = False
        
        if 'devices' in group_dict and group_dict.get('devices') is not None: # Only validate if devices key exists and is not None
            if 'identifier_type' not in group_dict or not group_dict.get('identifier_type'):
                errors.append("'identifier_type' is required and must be non-empty if 'devices' are specified.")
                final_is_valid = False
            elif group_dict.get('identifier_type') not in constants.VALID_IDENTIFIER_TYPES:
                errors.append(f"Invalid 'identifier_type': '{group_dict.get('identifier_type')}'. Valid types: {list(constants.VALID_IDENTIFIER_TYPES)}")
                final_is_valid = False
            # Further validation of 'devices' content (e.g. list of strings) could be added here or handled by parse_devices_input
            if not group_dict.get('devices'): # If 'devices' key exists but list is empty or None
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
    """Validates AD provider config when only 'Name' is needed for finding an existing provider."""
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
    """Validates minimal AD search credentials (Username, Password)."""
    context_name = f"AD Search Credentials from {source_info}"
    logger.debug(f"Validating minimal {context_name}...")
    # This validator only cares about Username and Password being present and of correct type.
    # It does not use AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.
    is_struct_valid, errors = validate_input(ad_creds_dict, constants.AD_CRED_REQUIRED_KEYS, context_name=context_name)
    final_is_valid = is_struct_valid

    if is_struct_valid:
        if not isinstance(ad_creds_dict.get('Username'), str) or not str(ad_creds_dict.get('Username')).strip():
            errors.append("AD 'Username' for search must be a non-empty string.")
            final_is_valid = False
        if 'Password' in ad_creds_dict and not isinstance(ad_creds_dict.get('Password'), str): # Password can be empty but must be string
            errors.append("AD 'Password' for search must be a string if provided.")
            final_is_valid = False
        elif 'Password' not in ad_creds_dict: # If password is required by AD_CRED_REQUIRED_KEYS
             errors.append("AD 'Password' key is required.")
             final_is_valid = False

    return final_is_valid, errors


def validate_ad_search_credentials_and_provider_name_specific(ad_config_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Validates AD Provider Name and AD Search Credentials together."""
    context_name = f"AD Search Credentials & Provider Name from {source_info}"
    logger.debug(f"Validating {context_name}...")
    # These are the keys expected when fetching AD Provider Name AND Search Credentials together
    # e.g. for AD Group Import workflow setup.
    required_keys = constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.union(constants.AD_CRED_REQUIRED_KEYS)
    is_struct_valid, errors = validate_input(ad_config_dict, required_keys, context_name=context_name)
    final_is_valid = is_struct_valid
    
    if is_struct_valid:
        if not isinstance(ad_config_dict.get('Name'), str) or not str(ad_config_dict.get('Name')).strip():
            errors.append("AD Provider 'Name' must be a non-empty string.")
            final_is_valid = False
        if not isinstance(ad_config_dict.get('Username'), str) or not str(ad_config_dict.get('Username')).strip():
            errors.append("AD 'Username' for search must be a non-empty string.")
            final_is_valid = False
        if 'Password' in ad_config_dict and not isinstance(ad_config_dict.get('Password'), str):
            errors.append("AD 'Password' for search must be a string if provided.")
            final_is_valid = False
        elif 'Password' not in ad_config_dict:
             errors.append("AD 'Password' key is required.")
             final_is_valid = False

    return final_is_valid, errors

def validate_ad_import_task_specific(import_task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Performs specific validation for a single AD import group task dictionary."""
    context_name = f"AD Import Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        import_task_dict,
        constants.AD_IMPORT_TASK_REQUIRED_KEYS,
        optional_keys=constants.AD_IMPORT_TASK_OPTIONAL_KEYS,
        context_name=context_name
    )
    final_is_valid = is_struct_valid

    if is_struct_valid:
        if not isinstance(import_task_dict.get('group_name'), str) or not str(import_task_dict.get('group_name')).strip():
            errors.append("'group_name' value must be a non-empty string.")
            final_is_valid = False
        
        if 'role_name' in import_task_dict and import_task_dict.get('role_name') is not None:
            if not isinstance(import_task_dict.get('role_name'), str) or not str(import_task_dict.get('role_name')).strip():
                errors.append("'role_name' value must be a non-empty string if provided.")
                final_is_valid = False
        
        # Validate 'Scope' field (key from user's original constants for this task)
        scope_key_to_check = 'Scope' # As per AD_IMPORT_TASK_OPTIONAL_KEYS
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

# --- NEW Validation Functions for OME Configuration Manager ---

def validate_ad_provider_payload_specific(payload_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Validates the full AD Provider configuration payload."""
    context_name = f"AD Provider Configuration Payload from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        payload_dict,
        constants.AD_PROVIDER_PAYLOAD_REQUIRED_KEYS,
        optional_keys=constants.AD_PROVIDER_PAYLOAD_OPTIONAL_KEYS,
        context_name=context_name
    )
    final_is_valid = is_struct_valid

    if is_struct_valid:
        # Type checks for required fields
        if not isinstance(payload_dict.get('Name'), str) or not payload_dict.get('Name', '').strip():
            errors.append("'Name' must be a non-empty string.")
            final_is_valid = False
        if payload_dict.get('ServerType') != "MANUAL": # As per manager script logic
             errors.append("'ServerType' must be 'MANUAL'.") # Or allow DNS and validate accordingly
             final_is_valid = False
        if not isinstance(payload_dict.get('ServerName'), list) or not payload_dict.get('ServerName') or \
           not all(isinstance(s, str) and s.strip() for s in payload_dict.get('ServerName', [])):
            errors.append("'ServerName' must be a non-empty list of non-empty strings (IPs/hostnames).")
            final_is_valid = False
        if not isinstance(payload_dict.get('UserName'), str): # Allow empty for anonymous bind if API supports
            errors.append("'UserName' (bind DN or UPN) must be a string.")
            final_is_valid = False
        if not isinstance(payload_dict.get('Password'), str):
            errors.append("'Password' (bind password) must be a string.")
            final_is_valid = False
        if not isinstance(payload_dict.get('ServerPort'), int) or not (0 < payload_dict.get('ServerPort',0) < 65536):
            errors.append("'ServerPort' must be a valid integer port number (1-65535).")
            final_is_valid = False
        if not isinstance(payload_dict.get('GroupDomain'), str): # Can be empty string
            errors.append("'GroupDomain' must be a string.")
            final_is_valid = False
        if not isinstance(payload_dict.get('NetworkTimeOut'), int) or payload_dict.get('NetworkTimeOut',0) <=0:
            errors.append("'NetworkTimeOut' must be a positive integer.")
            final_is_valid = False
        if not isinstance(payload_dict.get('SearchTimeOut'), int) or payload_dict.get('SearchTimeOut',0) <=0:
            errors.append("'SearchTimeOut' must be a positive integer.")
            final_is_valid = False

        # Type checks for optional fields if present
        if 'CertificateValidation' in payload_dict and not isinstance(payload_dict.get('CertificateValidation'), bool):
            errors.append("'CertificateValidation' must be a boolean if provided.")
            final_is_valid = False
        if 'CertificateFile' in payload_dict and not isinstance(payload_dict.get('CertificateFile'), str):
            errors.append("'CertificateFile' must be a string (path or content) if provided.")
            final_is_valid = False
            
    return final_is_valid, errors

def validate_ntp_payload_specific(payload_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Validates the NTP configuration payload."""
    context_name = f"NTP Configuration Payload from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        payload_dict,
        constants.NTP_CONFIG_REQUIRED_KEYS,
        optional_keys=constants.NTP_CONFIG_OPTIONAL_KEYS,
        context_name=context_name
    )
    final_is_valid = is_struct_valid

    if is_struct_valid:
        if not isinstance(payload_dict.get('EnableNTP'), bool):
            errors.append("'EnableNTP' must be a boolean.")
            final_is_valid = False
        if payload_dict.get('EnableNTP') and (not isinstance(payload_dict.get('PrimaryNTPAddress'), str) or not payload_dict.get('PrimaryNTPAddress','').strip()):
            errors.append("'PrimaryNTPAddress' must be a non-empty string if EnableNTP is true.")
            final_is_valid = False
        if payload_dict.get('EnableNTP') and (not isinstance(payload_dict.get('TimeZone'), str) or not payload_dict.get('TimeZone','').strip()):
            errors.append("'TimeZone' must be a non-empty string if EnableNTP is true.") # e.g. "TZ_ID_33"
            final_is_valid = False
        
        for key in ['SecondaryNTPAddress1', 'SecondaryNTPAddress2']:
            if key in payload_dict and payload_dict.get(key) is not None: # If present and not None
                if not isinstance(payload_dict.get(key), str) or not payload_dict.get(key,'').strip():
                    errors.append(f"'{key}' must be a non-empty string if provided and not null.")
                    final_is_valid = False
    return final_is_valid, errors

def validate_dns_servers_list_specific(servers_list: List[Any], source_info: str) -> Tuple[bool, List[str]]:
    """Validates a list of DNS server IPs/hostnames."""
    context_name = f"DNS Server List from {source_info}"
    logger.debug(f"Validating {context_name}...")
    errors = []
    is_valid = True

    if not isinstance(servers_list, list):
        errors.append("DNS servers input must be a list.")
        return False, errors
    
    min_dns, max_dns = constants.DNS_SERVERS_LIST_MIN_MAX
    if not (min_dns <= len(servers_list) <= max_dns):
        errors.append(f"Number of DNS servers must be between {min_dns} and {max_dns}. Found: {len(servers_list)}.")
        is_valid = False
    
    for i, server in enumerate(servers_list):
        if not isinstance(server, str) or not server.strip():
            errors.append(f"DNS server at index {i} must be a non-empty string.")
            is_valid = False
        # TODO: Add more specific IP/hostname format validation if needed
            
    return is_valid, errors

def validate_csr_details_payload_specific(payload_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Validates the CSR details payload (keys should match API expectations)."""
    # This validator expects keys like "DistinguishedName", "BusinessName" etc. (API keys)
    # The mapping from user-friendly names (common_name) to API keys happens in ome_config_manager.py
    # before calling this validator, or this validator needs to know about user-friendly keys.
    # Assuming payload_dict here contains keys that are about to be sent to OME API.
    # For now, let's define API_CSR_REQUIRED_KEYS and API_CSR_OPTIONAL_KEYS in constants.py if different.
    # Or, validate based on the user-friendly keys from constants.CSR_DETAILS_REQUIRED_KEYS.
    # Let's assume for now it validates the user-friendly input structure.
    
    context_name = f"CSR Details Payload from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        payload_dict,
        constants.CSR_DETAILS_REQUIRED_KEYS, # User-friendly keys
        optional_keys=constants.CSR_DETAILS_OPTIONAL_KEYS,
        context_name=context_name
    )
    final_is_valid = is_struct_valid

    if is_struct_valid:
        for key in constants.CSR_DETAILS_REQUIRED_KEYS:
            if not isinstance(payload_dict.get(key), str) or not payload_dict.get(key, '').strip():
                # key_size is an exception, it's int but API might take string.
                if key == 'key_size' and isinstance(payload_dict.get(key), int):
                    if payload_dict.get(key) not in constants.VALID_CSR_KEY_SIZES:
                        errors.append(f"'{key}' must be one of {constants.VALID_CSR_KEY_SIZES}.")
                        final_is_valid = False
                    continue # Valid int key_size
                elif key == 'key_size' and isinstance(payload_dict.get(key), str):
                    try:
                        if int(payload_dict.get(key,'0')) not in constants.VALID_CSR_KEY_SIZES:
                             errors.append(f"'{key}' string value must represent one of {constants.VALID_CSR_KEY_SIZES}.")
                             final_is_valid = False
                    except ValueError:
                        errors.append(f"'{key}' string value must be a valid integer representing one of {constants.VALID_CSR_KEY_SIZES}.")
                        final_is_valid = False
                    continue # Valid string key_size

                errors.append(f"Required CSR field '{key}' must be a non-empty string.")
                final_is_valid = False
        
        if 'key_size' in payload_dict: # Check if present, even if optional by structure
            ks = payload_dict['key_size']
            if not ((isinstance(ks, int) and ks in constants.VALID_CSR_KEY_SIZES) or \
                    (isinstance(ks, str) and ks.isdigit() and int(ks) in constants.VALID_CSR_KEY_SIZES)):
                errors.append(f"'key_size' ('{ks}') is invalid. Must be one of {constants.VALID_CSR_KEY_SIZES} (as int or string).")
                final_is_valid = False

        if 'country_code' in payload_dict and (not isinstance(payload_dict['country_code'], str) or len(payload_dict['country_code']) != 2):
            errors.append("'country_code' must be a 2-letter string.")
            final_is_valid = False
            
        if 'email_address' in payload_dict and payload_dict.get('email_address') is not None:
            if not isinstance(payload_dict.get('email_address'), str) or \
               ('@' not in payload_dict.get('email_address','') or '.' not in payload_dict.get('email_address','')): # Basic email check
                errors.append("Optional 'email_address' is not a valid format.")
                final_is_valid = False
        
        if 'subject_alternative_names_str' in payload_dict and payload_dict.get('subject_alternative_names_str') is not None:
            if not isinstance(payload_dict.get('subject_alternative_names_str'), str):
                 errors.append("Optional 'subject_alternative_names_str' must be a string (e.g., 'dns:name1,ip:addr1').")
                 final_is_valid = False
            # Further validation of SAN format could be added (e.g. each item starts with dns: or ip:)

    return final_is_valid, errors

def validate_plugin_action_task_specific(task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Validates a single plugin action task."""
    context_name = f"Plugin Action Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_struct_valid, errors = validate_input(
        task_dict,
        constants.PLUGIN_ACTION_TASK_REQUIRED_KEYS,
        context_name=context_name
    )
    final_is_valid = is_struct_valid

    if is_struct_valid:
        if not isinstance(task_dict.get('Id'), str) or not task_dict.get('Id','').strip(): # Typically GUID
            errors.append("'Id' (plugin GUID) must be a non-empty string.")
            final_is_valid = False
        if not isinstance(task_dict.get('Version'), str) or not task_dict.get('Version','').strip():
            errors.append("'Version' must be a non-empty string.")
            final_is_valid = False
        action = task_dict.get('Action')
        if not isinstance(action, str) or action not in constants.VALID_PLUGIN_ACTIONS:
            errors.append(f"'Action' ('{action}') is invalid. Must be one of {constants.VALID_PLUGIN_ACTIONS}.")
            final_is_valid = False
            
    return final_is_valid, errors

# For static group creation during initial setup, we reuse validate_static_group_definition_specific
# as per user's decision to use the comprehensive definition.
# If a simpler one was needed, a new validator would go here.
