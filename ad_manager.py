#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OME AD Group Import Manager script (v3.1.4).
Imports AD groups via OME provider, assigns roles (with default), adds scope.
Requires AD credentials for searching groups via OME.
"""

# __version__ = "3.1.3" # Previous version
__version__ = "3.1.4" # Pass ad_group_name to ome_client.import_ad_group

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-12 | 3.1.3   | Gemini     | Added AD username/password args & config. Pass creds to search_ad_group_in_ome_by_name.
# 2025-05-12 | 3.1.4   | Gemini     | Updated process_ad_import_task to pass ad_group_name to ome_client.import_ad_group.

import argparse
import sys
import logging
import json
import requests.exceptions
from typing import Dict, List, Optional, Tuple, Any

import utils
import constants # Ensure this is v1.2.3 or later
import input_validator # Ensure this is v1.2.2 or later
import ome_client # Ensure this is v1.10.9 or later

logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------
# Core Workflow Function
#------------------------------------------------------------------------------
def run_ad_import_workflow(ome_client_instance: ome_client.OmeClient,
                           ad_provider_id: int,
                           ad_provider_name_for_logging: str,
                           ad_search_username: str,
                           ad_search_password: str,
                           normalized_ad_import_tasks: List[Dict],
                           logger_instance: logging.Logger) -> bool:
    logger_instance.info(f"Starting processing of {len(normalized_ad_import_tasks)} AD group import task(s) using AD Provider '{ad_provider_name_for_logging}' (ID: {ad_provider_id})...")
    if not normalized_ad_import_tasks:
        logger_instance.info("No AD import tasks to process.")
        return True
    overall_success = True
    for import_task in normalized_ad_import_tasks:
        try:
            process_ad_import_task(
                ome_client_instance,
                ad_provider_id,
                ad_search_username,
                ad_search_password,
                import_task, # This dict contains 'group_name'
                logger_instance
            )
        except Exception as e:
            group_name = import_task.get('group_name', 'Unknown Task')
            logger_instance.error(f"Unexpected critical error during workflow for AD import task '{group_name}': {e}", exc_info=True)
            overall_success = False
    if not overall_success:
        logger_instance.warning("One or more AD import tasks encountered unexpected critical errors.")
    else:
        logger_instance.info("Finished processing all AD group import tasks.")
    return overall_success

#------------------------------------------------------------------------------
# Task Processing Function
#------------------------------------------------------------------------------
def process_ad_import_task(ome_client_instance: ome_client.OmeClient,
                           ad_provider_id: int,
                           ad_search_username: str,
                           ad_search_password: str,
                           import_task: Dict, # Contains 'group_name', 'role_name', 'scope_name'
                           logger: logging.Logger):
    ad_group_name = import_task.get('group_name') # Will be present
    role_name = import_task.get('role_name', constants.DEFAULT_AD_IMPORT_ROLE)
    scope_name = import_task.get('scope_name')
    logger.info(f"--- Processing AD group import: '{ad_group_name}' ---")
    logger.debug(f"Task Details: AD Group='{ad_group_name}', Role='{role_name}', Scope='{scope_name or 'None'}'")
    ad_group_guid: Optional[str] = None
    ome_role_id: Optional[str] = None
    imported_ome_account_id: Optional[str] = None
    try:
        logger.debug(f"Searching for AD group '{ad_group_name}' in OME via Provider ID {ad_provider_id} (using provided AD creds)...")
        ad_group_details = ome_client_instance.search_ad_group_in_ome_by_name(
            ad_provider_id, ad_group_name, ad_search_username, ad_search_password
        )
        if ad_group_details and ad_group_details.get('Guid'):
            ad_group_guid = str(ad_group_details['Guid'])
            logger.info(f"Found AD group '{ad_group_name}' with GUID: {ad_group_guid}")
        else: logger.error(f"AD group '{ad_group_name}' not found via OME search or GUID missing. Skipping."); return

        logger.debug(f"Finding OME Role ID for role name '{role_name}'...")
        ome_role_id_raw = ome_client_instance.get_role_id_by_name(role_name)
        if ome_role_id_raw:
            ome_role_id = str(ome_role_id_raw)
            logger.info(f"Found OME Role ID for '{role_name}': {ome_role_id}")
        else: logger.error(f"OME Role '{role_name}' not found. Skipping task for AD group '{ad_group_name}'."); return

        logger.debug(f"Checking if AD group (GUID: {ad_group_guid}) is already imported as a user in OME...")
        existing_ome_user_account = ome_client_instance.get_imported_ad_group_by_guid(ad_group_guid)
        if existing_ome_user_account:
             existing_ome_user_id_raw = existing_ome_user_account.get('Id')
             if existing_ome_user_id_raw is not None:
                 imported_ome_account_id = str(existing_ome_user_id_raw)
                 logger.warning(f"AD group '{ad_group_name}' already imported as user (Account ID: {imported_ome_account_id}). Skipping import.")
             else: logger.warning(f"AD group GUID '{ad_group_guid}' found imported but OME Account ID missing. Attempting import.")
        else: logger.debug(f"AD group GUID '{ad_group_guid}' not imported. Will proceed with import.")

        if not imported_ome_account_id:
            logger.info(f"Importing AD group '{ad_group_name}' (GUID: {ad_group_guid}) as user with Role ID {ome_role_id}...")
            try:
                # Pass ad_group_name to the client method for the new payload
                import_result_id = ome_client_instance.import_ad_group(
                    ad_provider_id, ad_group_name, ad_group_guid, ome_role_id # type: ignore
                )
                if import_result_id:
                    imported_ome_account_id = str(import_result_id)
                    logger.info(f"AD group '{ad_group_name}' imported as user. OME Account ID: {imported_ome_account_id}")
                else: logger.error(f"AD group import for '{ad_group_name}' failed or no OME Account ID returned. Skipping scope."); return
            except Exception as e: logger.error(f"Error importing AD group '{ad_group_name}' as user: {e}. Skipping scope.", exc_info=logger.isEnabledFor(logging.DEBUG)); return

        if scope_name and imported_ome_account_id:
            logger.info(f"Scope '{scope_name}' requested for imported AD user (Account ID: {imported_ome_account_id}). Searching...")
            scope_group_details = ome_client_instance.get_group_by_name(scope_name)
            if scope_group_details and scope_group_details.get('Id'):
                scope_group_id_str = str(scope_group_details.get('Id'))
                logger.info(f"Found scope group '{scope_name}' (ID: {scope_group_id_str}). Assigning scope...")
                try: ome_client_instance.add_scope_to_ad_group(imported_ome_account_id, scope_group_id_str)
                except Exception as e: logger.error(f"Error assigning scope '{scope_name}' to AD user '{ad_group_name}': {e}", exc_info=logger.isEnabledFor(logging.DEBUG))
            else: logger.warning(f"Static group for Scope ('{scope_name}') not found. Scope not assigned.")
        elif scope_name: logger.warning(f"Cannot process scope '{scope_name}' because AD group import/lookup as user failed for '{ad_group_name}'.")
    except Exception as e: logger.error(f"Unexpected error processing task for AD group '{ad_group_name}': {e}", exc_info=True)
    logger.info(f"--- Finished processing AD group import for '{ad_group_name}' ---")

#------------------------------------------------------------------------------
# Main execution block
#------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Import AD groups into OME using a pre-configured AD Provider.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    grp_ome = parser.add_argument_group('OME Connection Details');
    grp_ome.add_argument('--ome-url', metavar='URL'); grp_ome.add_argument('--username', metavar='USER'); grp_ome.add_argument('--password', metavar='PASS');
    grp_ad = parser.add_argument_group('AD Provider & Credentials');
    grp_ad.add_argument('--ad-name', dest='ad_name', help="Name of the pre-configured AD provider in OME", metavar='PROVIDER_NAME')
    grp_ad.add_argument('--ad-username', dest='ad_username', help="Username for AD (for searching groups via OME)", metavar='AD_USER')
    grp_ad.add_argument('--ad-password', dest='ad_password', help="Password for AD (for searching groups via OME)", metavar='AD_PASS')
    grp_input = parser.add_argument_group('Input Sources for AD Group Import Tasks');
    grp_input.add_argument('--config', help='Path to JSON config file', metavar='FILE_PATH');
    grp_input.add_argument(f'--{constants.AD_IMPORT_GROUP_CLI_ARG_NAME}', action='append', help=(f"JSON for AD import task. Keys: group_name (req), role_name (opt, def: {constants.DEFAULT_AD_IMPORT_ROLE}), Scope (opt)."), metavar='JSON_STRING')
    grp_log = parser.add_argument_group('Logging Options');
    grp_log.add_argument('--debug', action='store_true'); grp_log.add_argument('--log-file', metavar='LOG_FILE_PATH');
    args = parser.parse_args()

    utils.setup_logger(debug=args.debug, log_file_path=args.log_file)
    logger.info(f"OME AD Group Import script started (Version: {__version__}).")
    logger.debug(f"Parsed arguments: {args}")

    config: Optional[Dict] = None
    if args.config:
        config = utils.load_config(args.config, logger)
        if config is None: logger.fatal(f"Failed config load."); sys.exit(1)

    ome_creds, is_valid = utils.collect_and_validate_credentials(args, config, constants.OME_AUTH_REQUIRED_KEYS, constants.OME_CRED_CONFIG_SECTION, constants.OME_CLI_CRED_MAP, input_validator.validate_ome_credentials_specific, logger)
    if not is_valid: logger.fatal("Invalid OME credentials."); sys.exit(1)

    try:
        ome_client_instance = ome_client.OmeClient(ome_creds['url'], ome_creds['username'], ome_creds['password'])
        ome_client_instance.authenticate()
    except Exception as e: logger.fatal(f"Failed OME client setup/auth: {e}", exc_info=args.debug); sys.exit(1)

    ad_provider_id: Optional[int] = None
    ad_provider_name_for_logging: Optional[str] = None
    ad_search_username: Optional[str] = None
    ad_search_password: Optional[str] = None
    try:
        # AD_CONFIG_CLI_MAP now includes ad_name, ad_username, ad_password
        # AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.union(constants.AD_CRED_REQUIRED_KEYS) ensures Name, Username, Password are required
        ad_config, is_ad_config_valid = utils.collect_and_validate_credentials(
            args, config,
            constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.union(constants.AD_CRED_REQUIRED_KEYS),
            constants.AD_CONFIG_SECTION,
            constants.AD_CONFIG_CLI_MAP,
            input_validator.validate_ad_search_credentials_specific, # Validates Username & Password
            logger
        )
        if not is_ad_config_valid:
            logger.fatal("Invalid or missing AD Provider Name and/or AD Search Credentials."); sys.exit(1)

        ad_provider_name_for_logging = ad_config.get('Name')
        ad_search_username = ad_config.get('Username')
        ad_search_password = ad_config.get('Password')
        
        if not ad_provider_name_for_logging: # Should be caught by validator, but defensive
             logger.fatal("AD Provider Name is missing. Cannot proceed."); sys.exit(1)
        # ad_search_username and ad_search_password also checked by validator

        logger.info(f"Finding OME ID for Provider '{ad_provider_name_for_logging}'...")
        ad_provider_id = ome_client_instance.get_ad_provider_id_by_name(ad_provider_name_for_logging)
        if not ad_provider_id:
             logger.fatal(f"AD Provider '{ad_provider_name_for_logging}' not found or missing ID in OME."); sys.exit(1)
        logger.info(f"Using AD Provider ID: {ad_provider_id}")

    except Exception as e: logger.fatal(f"Error handling AD provider/credentials: {e}", exc_info=args.debug); sys.exit(1)

    valid_raw_ad_imports, invalid_ad_import_details = utils.collect_and_validate_list_inputs(args, config, constants.AD_IMPORT_GROUP_CLI_ARG_NAME, constants.AD_IMPORT_GROUP_CONFIG_SECTION, input_validator.validate_ad_import_task_specific, logger)
    total_cli_tasks = len(getattr(args, constants.AD_IMPORT_GROUP_CLI_ARG_NAME, [])); cfg_list = utils.get_config_section(config, constants.AD_IMPORT_GROUP_CONFIG_SECTION, []); total_cfg_tasks = len(cfg_list) if isinstance(cfg_list, list) else 0
    if (total_cli_tasks + total_cfg_tasks) == 1 and not valid_raw_ad_imports: logger.fatal("Single AD import task invalid."); sys.exit(1)
    if invalid_ad_import_details:
        logger.warning(f"Skipping {len(invalid_ad_import_details)} invalid AD import task(s):")
        for item, errors, src in invalid_ad_import_details: logger.error(f"  Invalid {src}: {item} -> {errors}")

    normalized_ad_import_tasks: List[Dict] = []
    for raw_task_dict in valid_raw_ad_imports:
         role = raw_task_dict.get('role_name') or constants.DEFAULT_AD_IMPORT_ROLE
         if not raw_task_dict.get('role_name'): logger.debug(f"Using default role '{role}' for group '{raw_task_dict['group_name']}'")
         normalized_ad_import_tasks.append({"group_name": raw_task_dict['group_name'], "role_name": role, "scope_name": raw_task_dict.get('Scope')})
    if not normalized_ad_import_tasks: logger.info("No valid tasks to process."); sys.exit(0)

    exit_code = 0
    try:
        workflow_success = run_ad_import_workflow(
            ome_client_instance,
            ad_provider_id, # type: ignore
            ad_provider_name_for_logging, # type: ignore
            ad_search_username, # type: ignore
            ad_search_password, # type: ignore
            normalized_ad_import_tasks,
            logger
        )
        if not workflow_success: logger.warning("Workflow completed with issues.")
    except Exception as e: logger.fatal(f"Core workflow failed: {e}", exc_info=True); exit_code = 1
    logger.info(f"Script finished with exit code {exit_code}."); sys.exit(exit_code)

if __name__ == "__main__":
    main()
