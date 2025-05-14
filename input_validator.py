# -*- coding: utf-8 -*-
"""Contains specific validation logic"""

# __version__ = "1.2.2" # Previous version
__version__ = "1.2.3" # Allow Scope to be string or list of strings in AD import task

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ...
# 2025-05-12 | 1.2.2   | Gemini     | Added validate_ad_search_credentials_specific for AD username/password.
# 2025-05-15 | 1.2.3   | Gemini     | Modified validate_ad_import_task_specific to allow 'Scope' to be a string or a list of strings.

import logging
import constants # Ensure this is constants_v1_2_3_final or later
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
        errors.append(f"Missing required key(s): {', '.join(sorted(list(missing_keys)))}")
        is_valid = False
    return is_valid, errors

def validate_ome_credentials_specific(credentials_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    logger.debug(f"Validating OME credentials from {source_info}...")
    is_valid, errors = validate_input(credentials_dict, constants.OME_AUTH_REQUIRED_KEYS, context_name=f"OME Credentials from {source_info}")
    if is_valid:
        if not isinstance(credentials_dict.get('url'), str) or not credentials_dict.get('url', '').strip(): errors.append("'url' must be non-empty string.")
        if not isinstance(credentials_dict.get('username'), str) or not credentials_dict.get('username', '').strip(): errors.append("'username' must be non-empty string.")
        if not isinstance(credentials_dict.get('password'), str): errors.append("'password' must be a string.")
    is_valid = (len(errors) == 0) and is_valid
    return is_valid, errors

def validate_static_group_definition_specific(group_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    logger.debug(f"Validating static group from {source_info}...")
    is_valid, errors = validate_input(group_dict, constants.STATIC_GROUP_REQUIRED_KEYS, optional_keys=constants.STATIC_GROUP_OPTIONAL_KEYS, context_name=f"Static Group from {source_info}")
    if 'group_name' in group_dict and (not isinstance(group_dict.get('group_name'), str) or not str(group_dict.get('group_name')).strip()): errors.append("'group_name' must be non-empty string."); is_valid = False
    if 'devices' in group_dict:
        if 'identifier_type' not in group_dict: errors.append("'identifier_type' required with 'devices'."); is_valid = False
        elif group_dict.get('identifier_type') not in constants.VALID_IDENTIFIER_TYPES: errors.append(f"Invalid 'identifier_type'. Valid: {list(constants.VALID_IDENTIFIER_TYPES)}"); is_valid = False
    if 'create' in group_dict and not isinstance(group_dict.get('create'), bool): errors.append("'create' must be boolean."); is_valid = False
    if 'parent_group' in group_dict and (not isinstance(group_dict.get('parent_group'), str) or not str(group_dict.get('parent_group')).strip()): errors.append("'parent_group' must be non-empty string."); is_valid = False
    is_valid = (len(errors) == 0) and is_valid
    return is_valid, errors

def validate_ad_provider_config_specific(ad_config_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Validates AD provider config - only 'Name' for finding existing."""
    context_name=f"AD Provider Config from {source_info}"
    logger.debug(f"Validating {context_name} (checking only Name)...")
    required_keys = constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND
    is_valid, errors = validate_input(ad_config_dict, required_keys, context_name=context_name)
    if 'Name' in ad_config_dict and (not isinstance(ad_config_dict.get('Name'), str) or not str(ad_config_dict.get('Name')).strip()):
        errors.append("'Name' (for AD Provider) must be a non-empty string.")
        is_valid = False
    is_valid = (len(errors) == 0) and is_valid
    return is_valid, errors

def validate_ad_search_credentials_specific(ad_creds_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Validates AD credentials (Username, Password) for the search operation."""
    context_name = f"AD Search Credentials & Provider Name from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_valid, errors = validate_input(
        ad_creds_dict,
        constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.union(constants.AD_CRED_REQUIRED_KEYS),
        context_name=context_name
    )
    if 'Name' in ad_creds_dict and (not isinstance(ad_creds_dict.get('Name'), str) or not str(ad_creds_dict.get('Name')).strip()):
        errors.append("AD Provider 'Name' must be a non-empty string.")
        is_valid = False
    if 'Username' in ad_creds_dict and (not isinstance(ad_creds_dict.get('Username'), str) or not str(ad_creds_dict.get('Username')).strip()):
        errors.append("AD 'Username' for search must be a non-empty string.")
        is_valid = False
    if 'Password' in ad_creds_dict and not isinstance(ad_creds_dict.get('Password'), str):
        errors.append("AD 'Password' for search must be a string.")
        is_valid = False
    is_valid = (len(errors) == 0) and is_valid
    return is_valid, errors

def validate_ad_import_task_specific(import_task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Performs specific validation for a single AD import group task dictionary."""
    context_name = f"AD Import Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_valid, errors = validate_input(
        import_task_dict,
        constants.AD_IMPORT_TASK_REQUIRED_KEYS,
        optional_keys=constants.AD_IMPORT_TASK_OPTIONAL_KEYS,
        context_name=context_name
    )
    if 'group_name' in import_task_dict and (not isinstance(import_task_dict.get('group_name'), str) or not str(import_task_dict.get('group_name')).strip()):
        errors.append("'group_name' value must be a non-empty string.")
        is_valid = False
    if 'role_name' in import_task_dict and import_task_dict.get('role_name') is not None and \
       (not isinstance(import_task_dict.get('role_name'), str) or not str(import_task_dict.get('role_name')).strip()):
        errors.append("'role_name' value must be a non-empty string if provided.")
        is_valid = False
    
    # Validate 'Scope' field: can be a non-empty string or a list of non-empty strings
    if 'Scope' in import_task_dict and import_task_dict.get('Scope') is not None:
        scope_value = import_task_dict.get('Scope')
        if isinstance(scope_value, str):
            if not scope_value.strip():
                errors.append("'Scope' string value must be non-empty if provided.")
                is_valid = False
        elif isinstance(scope_value, list):
            if not scope_value: # Empty list
                errors.append("'Scope' list must not be empty if provided as a list.")
                is_valid = False
            for i, item in enumerate(scope_value):
                if not isinstance(item, str) or not item.strip():
                    errors.append(f"'Scope' list item at index {i} must be a non-empty string.")
                    is_valid = False
        else:
            errors.append("'Scope' value must be a non-empty string or a list of non-empty strings if provided.")
            is_valid = False
            
    is_valid = (len(errors) == 0) and is_valid
    return is_valid, errors
