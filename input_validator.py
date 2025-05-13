# -*- coding: utf-8 -*-
"""Contains specific validation logic"""

# __version__ = "1.2.0" # Previous version
__version__ = "1.2.1" # Incremented version

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ...
# 2025-05-06 | 1.2.0   | Gemini     | Updated AD provider validator for more config fields. Made role_name optional in AD import task validator.
# 2025-05-06 | 1.2.1   | Gemini     | Simplified validate_ad_provider_config_specific to only check 'Name' (removed require_all_config_keys flag).

import logging
import constants
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

# General validate_input helper (no changes needed)
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


# --- Specific Validation Functions ---

def validate_ome_credentials_specific(credentials_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    # (No changes needed)
    logger.debug(f"Validating OME credentials from {source_info}...")
    is_valid, errors = validate_input(credentials_dict, constants.OME_AUTH_REQUIRED_KEYS, context_name=f"OME Credentials from {source_info}")
    if is_valid:
        if not isinstance(credentials_dict.get('url'), str) or not credentials_dict.get('url', '').strip(): errors.append("'url' must be non-empty string.")
        if not isinstance(credentials_dict.get('username'), str) or not credentials_dict.get('username', '').strip(): errors.append("'username' must be non-empty string.")
        if not isinstance(credentials_dict.get('password'), str): errors.append("'password' must be a string.")
    is_valid = (len(errors) == 0) and is_valid
    return is_valid, errors

def validate_static_group_definition_specific(group_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    # (No changes needed)
    logger.debug(f"Validating static group from {source_info}...")
    is_valid, errors = validate_input(group_dict, constants.STATIC_GROUP_REQUIRED_KEYS, optional_keys=constants.STATIC_GROUP_OPTIONAL_KEYS, context_name=f"Static Group from {source_info}")
    if 'group_name' in group_dict and (not isinstance(group_dict.get('group_name'), str) or not str(group_dict.get('group_name')).strip()): errors.append("'group_name' must be non-empty string."); is_valid = False
    if 'devices' in group_dict:
        if 'identifier_type' not in group_dict: errors.append("'identifier_type' required with 'devices'."); is_valid = False
        elif group_dict.get('identifier_type') not in constants.VALID_IDENTIFIER_TYPES: errors.append(f"Invalid 'identifier_type'. Valid: {constants.VALID_IDENTIFIER_TYPES}"); is_valid = False
    if 'create' in group_dict and not isinstance(group_dict.get('create'), bool): errors.append("'create' must be boolean."); is_valid = False
    if 'parent_group' in group_dict and (not isinstance(group_dict.get('parent_group'), str) or not str(group_dict.get('parent_group')).strip()): errors.append("'parent_group' must be non-empty string."); is_valid = False
    is_valid = (len(errors) == 0) and is_valid
    return is_valid, errors


# --- SIMPLIFIED: AD Provider Config Validator ---
def validate_ad_provider_config_specific(ad_config_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """
    Validates the AD provider configuration - now only checks for 'Name'.
    """
    context_name=f"AD Provider Config from {source_info}"
    logger.debug(f"Validating {context_name} (checking only Name)...")

    # Only require the 'Name' key for finding the provider
    required_keys = constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND
    optional_keys = None # Not checking other keys here

    is_valid, errors = validate_input(
        ad_config_dict,
        required_keys,
        optional_keys=optional_keys,
        context_name=context_name
    )

    # Basic Value Check for Name
    if 'Name' in ad_config_dict and (not isinstance(ad_config_dict.get('Name'), str) or not str(ad_config_dict.get('Name')).strip()):
        errors.append("'Name' must be a non-empty string.")
        is_valid = False

    is_valid = (len(errors) == 0) and is_valid
    return is_valid, errors


# --- AD Import Task Validator (No change from v1.2.0) ---
def validate_ad_import_task_specific(import_task_dict: Dict, source_info: str) -> Tuple[bool, List[str]]:
    """Performs specific validation for a single AD import group task dictionary."""
    context_name = f"AD Import Task from {source_info}"
    logger.debug(f"Validating {context_name}...")
    is_valid, errors = validate_input(
        import_task_dict,
        constants.AD_IMPORT_TASK_REQUIRED_KEYS, # Only group_name required
        optional_keys=constants.AD_IMPORT_TASK_OPTIONAL_KEYS, # role_name, Scope optional
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
