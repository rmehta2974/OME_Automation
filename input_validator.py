# -*- coding: utf-8 -*-
"""Contains specific validation logic"""

# __version__ = "1.2.1" # Previous version (from immersive input_validator_v1_2_1)
__version__ = "1.2.2" # Added validate_ad_search_credentials_specific

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history from input_validator_v1_2_1) ...
# 2025-05-12 | 1.2.1   | Rahul Mehta    | Simplified validate_ad_provider_config_specific to only check 'Name'.
# 2025-05-13 | 1.2.2   | Rahul Mehta    | Added validate_ad_search_credentials_specific for AD username/password used in search.

import logging
import constants # Ensure this points to constants_v1_2_3_final
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
    """
    Validates AD provider config - only 'Name' for finding existing.
    This validator is used when we only need the Name to find the provider.
    If AD credentials are also collected in the same step, they should be validated by a different or combined validator.
    """
    context_name=f"AD Provider Name Config from {source_info}"
    logger.debug(f"Validating {context_name} (checking only Name)...")
    required_keys = constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND # {'Name'}
    is_valid, errors = validate_input(ad_config_dict, required_keys, context_name=context_name)

    if 'Name' in ad_config_dict and (not isinstance(ad_config_dict.get('Name'), str) or not str(ad_config_dict.get('Name')).strip()):
        errors.append("'Name' (for AD Provider) must be a non-empty string.")
        is_valid = False
    is_valid = (len(errors) == 0) and is_valid
    return is_valid, errors

# --- NEW: Validator for AD Credentials used in Search ---
def validate_ad_search_credentials_specific(ad_creds_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """
    Validates AD credentials (Username, Password) for the search operation.
    Also implicitly checks for 'Name' if it's part of the required_keys passed to utils.collect_and_validate_credentials.
    """
    context_name = f"AD Search Credentials & Provider Name from {source_info}"
    logger.debug(f"Validating {context_name}...")
    # The calling function in ad_import_manager.py will pass required_keys that include Name, Username, Password
    # So, validate_input will check for their presence. Here we do value checks.
    is_valid, errors = validate_input(
        ad_creds_dict,
        constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.union(constants.AD_CRED_REQUIRED_KEYS), # Ensures Name, Username, Password are checked for presence
        context_name=context_name
    )

    # Value check for Name (even though presence is checked by validate_input)
    if 'Name' in ad_creds_dict and (not isinstance(ad_creds_dict.get('Name'), str) or not str(ad_creds_dict.get('Name')).strip()):
        errors.append("AD Provider 'Name' must be a non-empty string.")
        is_valid = False

    # Value checks for AD search credentials
    if 'Username' in ad_creds_dict and (not isinstance(ad_creds_dict.get('Username'), str) or not str(ad_creds_dict.get('Username')).strip()):
        errors.append("AD 'Username' for search must be a non-empty string.")
        is_valid = False
    if 'Password' in ad_creds_dict and not isinstance(ad_creds_dict.get('Password'), str): # Allow empty password if AD permits
        errors.append("AD 'Password' for search must be a string.")
        is_valid = False

    is_valid = (len(errors) == 0) and is_valid # Update validity based on these specific checks
    return is_valid, errors

def validate_ad_import_task_specific(import_task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
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
    if 'Scope' in import_task_dict and import_task_dict.get('Scope') is not None and \
       (not isinstance(import_task_dict.get('Scope'), str) or not str(import_task_dict.get('Scope')).strip()):
        errors.append("'Scope' value must be a non-empty string if provided.")
        is_valid = False
    is_valid = (len(errors) == 0) and is_valid
    return is_valid, errors
