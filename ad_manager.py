#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OME AD Group Import Manager script (v3.1.10).
Imports AD groups via OME provider, assigns roles (with default), adds scope.
Requires AD credentials for searching groups via OME.
Checks for existing OME account by UserName before import.
Handles various scope_name input formats (None, string, list, comma-separated string).
"""

# __version__ = "3.1.9" # Previous version
__version__ = "3.1.10" # Corrected input_validator function call for AD search credentials.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-16 | 3.1.9   | Rahul Mehta     | Removed logger instance passing to utils.setup_logger() and ome_client.OmeClient()
#            |         |            | constructor based on user feedback about original implementation.
# 2025-05-15 | 3.1.10  | Rahul Mehta     | Updated call to input_validator to use
#            |         |            | validate_ad_search_credentials_and_provider_name_specific
#            |         |            | to align with input_validator.py v1.2.4.

import argparse
import sys
import logging
import json 
from typing import Dict, List, Optional, Tuple, Any 

import utils 
import constants 
import input_validator 
import ome_client 

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
                import_task,
                logger_instance 
            )
        except Exception as e:
            group_name_for_error = import_task.get('group_name', 'Unknown Task')
            logger_instance.error(f"Unexpected critical error during workflow for AD import task '{group_name_for_error}': {e}", exc_info=True)
            overall_success = False 

    if not overall_success:
        logger_instance.warning("One or more AD import tasks encountered unexpected critical errors during the workflow.")
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
                           import_task: Dict,
                           logger: logging.Logger): 
    ad_group_name = import_task.get('group_name')
    role_name = import_task.get('role_name', constants.DEFAULT_AD_IMPORT_ROLE)
    raw_scope_input = import_task.get('scope_name')

    logger.info(f"--- Processing AD group import: '{ad_group_name}' ---")
    logger.debug(f"Task Details: AD Group='{ad_group_name}', Role='{role_name}', Raw Scope Input='{raw_scope_input or 'None'}'")

    ad_object_guid: Optional[str] = None
    ome_role_id: Optional[str] = None
    imported_ome_account_id_str: Optional[str] = None

    try:
        logger.debug(f"Searching for AD group '{ad_group_name}' in OME via Provider ID {ad_provider_id}...")
        ad_group_details = ome_client_instance.search_ad_group_in_ome_by_name(
            ad_provider_id, ad_group_name, ad_search_username, ad_search_password
        )
        if ad_group_details and ad_group_details.get('ObjectGuid'):
            ad_object_guid = str(ad_group_details['ObjectGuid'])
            logger.info(f"Found AD group '{ad_group_name}' with ObjectGuid: {ad_object_guid}")
        else:
            logger.error(f"AD group '{ad_group_name}' not found via OME search or ObjectGuid missing. Skipping task.")
            return

        logger.debug(f"Finding OME Role ID for role name '{role_name}'...")
        ome_role_id_raw = ome_client_instance.get_role_id_by_name(role_name)
        if ome_role_id_raw:
            ome_role_id = str(ome_role_id_raw)
            logger.info(f"Found OME Role ID for '{role_name}': {ome_role_id}")
        else:
            logger.error(f"OME Role '{role_name}' not found. Skipping task for AD group '{ad_group_name}'.")
            return

        logger.info(f"Checking if OME Account with UserName '{ad_group_name}' already exists...")
        existing_ome_account = ome_client_instance.get_imported_ad_account_by_username(ad_group_name)
        if existing_ome_account:
            existing_ome_account_id_raw = existing_ome_account.get('Id')
            if existing_ome_account_id_raw is not None:
                imported_ome_account_id_str = str(existing_ome_account_id_raw)
                found_object_guid_on_ome = existing_ome_account.get('ObjectGuid', 'NOT_FOUND_ON_OME_ACCOUNT')
                logger.warning(f"OME Account with UserName '{ad_group_name}' already exists (ID: {imported_ome_account_id_str}). Its ObjectGuid on OME: '{found_object_guid_on_ome}'. Searched AD group ObjectGuid: '{ad_object_guid}'. Skipping import, will proceed to scope assignment if applicable.")
            else:
                logger.warning(f"OME Account with UserName '{ad_group_name}' found but its OME Account ID is missing. Attempting fresh import as a precaution.")
        else:
            logger.info(f"OME Account with UserName '{ad_group_name}' not found. Will proceed with import.")

        if not imported_ome_account_id_str:
            logger.info(f"Attempting to import AD group '{ad_group_name}' (ObjectGuid: {ad_object_guid}) as user with Role ID {ome_role_id}...")
            try:
                import_result_id = ome_client_instance.import_ad_group(
                    ad_provider_id, ad_group_name, ad_object_guid, ome_role_id # type: ignore
                )
                if import_result_id:
                    imported_ome_account_id_str = str(import_result_id)
                    logger.info(f"AD group '{ad_group_name}' imported as user. New OME Account ID: {imported_ome_account_id_str}")
                else:
                    logger.error(f"AD group import for '{ad_group_name}' failed or returned no OME Account ID. Skipping scope assignment.")
                    return
            except Exception as e:
                logger.error(f"Error during AD group import for '{ad_group_name}': {e}. Skipping scope assignment.", exc_info=logger.isEnabledFor(logging.DEBUG))
                return

        individual_scope_names_to_process: List[str] = []
        if isinstance(raw_scope_input, list):
            for item in raw_scope_input:
                if isinstance(item, str):
                    item_stripped = item.strip()
                    if item_stripped:
                        individual_scope_names_to_process.append(item_stripped)
                    else:
                        logger.warning(f"Empty scope name found in list for AD group '{ad_group_name}'. Skipping it.")
                else:
                    logger.warning(f"Non-string item '{item}' in scope list for AD group '{ad_group_name}'. Skipping it.")
        elif isinstance(raw_scope_input, str):
            raw_scope_input_stripped = raw_scope_input.strip()
            if not raw_scope_input_stripped:
                logger.info(f"Scope input for AD group '{ad_group_name}' is an empty string. No specific scopes to process by name.")
            elif ',' in raw_scope_input_stripped:
                names = [s.strip() for s in raw_scope_input_stripped.split(',') if s.strip()]
                if names:
                    individual_scope_names_to_process.extend(names)
                else:
                    logger.warning(f"Comma-separated scope string '{raw_scope_input_stripped}' for AD group '{ad_group_name}' resulted in no valid scope names after parsing.")
            else:
                individual_scope_names_to_process.append(raw_scope_input_stripped)
        elif raw_scope_input is not None:
            logger.warning(f"Unexpected type for scope_name: {type(raw_scope_input)} for AD group '{ad_group_name}'. Attempting to treat as string.")
            try:
                fallback_str_scope = str(raw_scope_input).strip()
                if fallback_str_scope:
                    if ',' in fallback_str_scope:
                        names = [s.strip() for s in fallback_str_scope.split(',') if s.strip()]
                        if names: individual_scope_names_to_process.extend(names)
                    else:
                        individual_scope_names_to_process.append(fallback_str_scope)
                else:
                    logger.warning(f"Fallback conversion of scope value '{raw_scope_input}' for AD group '{ad_group_name}' resulted in an empty string.")
            except Exception as e:
                logger.error(f"Could not convert unexpected scope type '{type(raw_scope_input)}' to string for AD group '{ad_group_name}': {e}")

        if imported_ome_account_id_str and raw_scope_input is not None:
            logger.info(f"Attempting to set scopes for OME Account ID: {imported_ome_account_id_str} (AD Group: '{ad_group_name}') based on requested scope name(s).")
            collected_scope_group_ids_as_str: List[str] = []
            if individual_scope_names_to_process:
                for s_name_to_find in individual_scope_names_to_process:
                    logger.debug(f"Searching for OME static group (scope) '{s_name_to_find}' to get its ID...")
                    scope_group_details = ome_client_instance.get_group_by_name(s_name_to_find)
                    if scope_group_details and scope_group_details.get('Id') is not None:
                        scope_group_id_str = str(scope_group_details.get('Id'))
                        if scope_group_id_str.strip():
                            collected_scope_group_ids_as_str.append(scope_group_id_str)
                            logger.info(f"Found OME static group (scope) '{s_name_to_find}' with ID: {scope_group_id_str}.")
                        else:
                            logger.warning(f"OME static group (scope) '{s_name_to_find}' found but its ID is empty. Skipping this scope.")
                    else:
                        logger.warning(f"OME static group (scope) ('{s_name_to_find}') not found or its ID is missing. This scope will not be included.")
            try:
                logger.info(f"Calling 'add_scope_to_ad_group' for OME Account ID {imported_ome_account_id_str} with resolved static group IDs: {collected_scope_group_ids_as_str}")
                ome_client_instance.add_scope_to_ad_group(
                    imported_ome_account_id_str, 
                    collected_scope_group_ids_as_str  
                ) 
                logger.info(f"Call to 'add_scope_to_ad_group' completed for OME Account ID {imported_ome_account_id_str}.")
            except Exception as e:
                logger.error(f"Error occurred during the call to 'add_scope_to_ad_group' for OME Account ID {imported_ome_account_id_str}: {e}", exc_info=logger.isEnabledFor(logging.DEBUG))
        elif imported_ome_account_id_str and raw_scope_input is None:
            logger.info(f"No 'scope_name' provided in the import task for AD group '{ad_group_name}' (OME Account ID: {imported_ome_account_id_str}). Existing scopes will remain unchanged.")
        elif not imported_ome_account_id_str and raw_scope_input is not None:
            logger.warning(f"Cannot process scopes (input: '{raw_scope_input}') because OME Account ID for AD group '{ad_group_name}' could not be determined.")

    except Exception as e:
        logger.error(f"Unexpected error processing task for AD group '{ad_group_name}': {e}", exc_info=True)
    finally:
        logger.info(f"--- Finished processing AD group import for '{ad_group_name}' ---")

#------------------------------------------------------------------------------
# Main execution block
#------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Import AD groups into OME using a pre-configured AD Provider.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    grp_ome = parser.add_argument_group('OME Connection Details')
    grp_ome.add_argument('--ome-url', metavar='URL', help="URL for the OME instance (e.g., https://ome.example.com)")
    grp_ome.add_argument('--username', metavar='USER', help="OME username for authentication")
    grp_ome.add_argument('--password', metavar='PASS', help="OME password for authentication")

    grp_ad = parser.add_argument_group('AD Provider & Credentials')
    grp_ad.add_argument('--ad-name', dest='ad_name', help="Name of the pre-configured AD provider in OME", metavar='PROVIDER_NAME')
    grp_ad.add_argument('--ad-username', dest='ad_username', help="Username for AD (for searching groups via OME)", metavar='AD_USER')
    grp_ad.add_argument('--ad-password', dest='ad_password', help="Password for AD (for searching groups via OME)", metavar='AD_PASS')

    grp_input = parser.add_argument_group('Input Sources for AD Group Import Tasks')
    grp_input.add_argument('--config', help='Path to JSON config file containing connection details and/or import tasks', metavar='FILE_PATH')
    ad_group_task_help = (
        f"JSON string for a single AD import task. Keys: 'group_name' (required), "
        f"'role_name' (optional, default: {constants.DEFAULT_AD_IMPORT_ROLE}), "
        f"'scope_name' (optional, can be string or list of strings). Can be used multiple times."
    )
    grp_input.add_argument(
        f'--{constants.AD_IMPORT_GROUP_CLI_ARG_NAME}', # Should be 'adgroup'
        action='append',
        help=ad_group_task_help,
        metavar='JSON_STRING'
    )

    grp_log = parser.add_argument_group('Logging Options')
    grp_log.add_argument('--debug', action='store_true', help="Enable debug level logging")
    grp_log.add_argument('--log-file', metavar='LOG_FILE_PATH', help="Path to a file for logging output")
    args = parser.parse_args()

    utils.setup_logger(debug=args.debug, log_file_path=args.log_file)
    logger.info(f"OME AD Group Import script started (Version: {__version__}).")
    logger.debug(f"Parsed arguments: {args}")

    config: Optional[Dict] = None
    if args.config:
        config = utils.load_config(args.config, logger)
        if config is None:
            logger.fatal(f"Failed to load configuration from '{args.config}'. Exiting.")
            sys.exit(1)

    ome_creds, is_ome_creds_valid = utils.collect_and_validate_credentials(
        args, config, constants.OME_AUTH_REQUIRED_KEYS,
        constants.OME_CRED_CONFIG_SECTION, constants.OME_CLI_CRED_MAP,
        input_validator.validate_ome_credentials_specific, logger
    )
    if not is_ome_creds_valid:
        logger.fatal("Invalid OME credentials. Exiting.")
        sys.exit(1)

    ome_client_instance: Optional[ome_client.OmeClient] = None
    try:
        logger.debug(f"Initializing OME client for URL: {ome_creds.get('url')}")
        ome_client_instance = ome_client.OmeClient(
            ome_creds['url'], ome_creds['username'], ome_creds['password']
        )
        ome_client_instance.authenticate()
        logger.info("Successfully authenticated with OME.")
    except Exception as e:
        logger.fatal(f"Failed OME client setup or authentication: {e}", exc_info=args.debug)
        sys.exit(1)

    ad_provider_id: Optional[int] = None
    ad_provider_name_for_logging: Optional[str] = None
    ad_search_username_val: Optional[str] = None
    ad_search_password_val: Optional[str] = None
    try:
        # This collects AD Provider Name and AD Search Credentials
        ad_config_data, is_ad_config_valid = utils.collect_and_validate_credentials(
            args, config,
            # Required keys for this operation: AD Provider Name + AD Search Username/Password
            constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.union(constants.AD_CRED_REQUIRED_KEYS),
            constants.AD_CONFIG_SECTION, # 'ActiveDirectory'
            constants.AD_CONFIG_CLI_MAP, # Maps --ad-name, --ad-username, --ad-password
            # Use the validator that checks for Name, Username, and Password
            input_validator.validate_ad_search_credentials_and_provider_name_specific, # CORRECTED VALIDATOR
            logger
        )
        if not is_ad_config_valid:
            logger.fatal("Invalid or missing AD Provider Name and/or AD Search Credentials. Exiting.")
            sys.exit(1)

        ad_provider_name_for_logging = ad_config_data.get('Name')
        ad_search_username_val = ad_config_data.get('Username')
        ad_search_password_val = ad_config_data.get('Password')
        
        if not ad_provider_name_for_logging: 
            logger.fatal("AD Provider Name is missing after validation. Cannot proceed. Exiting.")
            sys.exit(1)
        if ad_search_username_val is None or ad_search_password_val is None: 
             logger.fatal("AD search username or password missing after validation. Exiting.")
             sys.exit(1)

        logger.info(f"Finding OME ID for AD Provider '{ad_provider_name_for_logging}'...")
        ad_provider_id_raw = ome_client_instance.get_ad_provider_id_by_name(ad_provider_name_for_logging)
        if ad_provider_id_raw is None:
            logger.fatal(f"AD Provider '{ad_provider_name_for_logging}' not found or has no ID in OME. Exiting.")
            sys.exit(1)
        try:
            ad_provider_id = int(ad_provider_id_raw)
        except ValueError:
            logger.fatal(f"AD Provider ID '{ad_provider_id_raw}' for '{ad_provider_name_for_logging}' is not a valid integer. Exiting.")
            sys.exit(1)
        logger.info(f"Using AD Provider ID: {ad_provider_id} for '{ad_provider_name_for_logging}'.")

    except Exception as e:
        logger.fatal(f"Error handling AD provider configuration or credentials: {e}", exc_info=args.debug)
        sys.exit(1)

    valid_raw_ad_imports, invalid_ad_import_details = utils.collect_and_validate_list_inputs(
        args, config,
        constants.AD_IMPORT_GROUP_CLI_ARG_NAME, # 'adgroup'
        constants.AD_IMPORT_GROUP_CONFIG_SECTION, # 'ADImportGroup'
        input_validator.validate_ad_import_task_specific,
        logger
    )
    
    cli_ad_tasks_value = getattr(args, constants.AD_IMPORT_GROUP_CLI_ARG_NAME, None)
    total_cli_tasks = len(cli_ad_tasks_value) if cli_ad_tasks_value is not None else 0
    config_ad_tasks_list = utils.get_config_section(config, constants.AD_IMPORT_GROUP_CONFIG_SECTION, [])
    total_config_tasks = len(config_ad_tasks_list) if isinstance(config_ad_tasks_list, list) else 0
    
    if (total_cli_tasks + total_config_tasks) == 0: # No tasks provided at all
        logger.info("No AD import tasks defined in CLI arguments or config file. Nothing to do for AD import.")
    elif (total_cli_tasks + total_config_tasks) == 1 and not valid_raw_ad_imports: # Single task provided and it's invalid
        logger.fatal("Single AD import task provided, and it is invalid. Exiting.")
        sys.exit(1)

    if invalid_ad_import_details:
        logger.warning(f"Skipping {len(invalid_ad_import_details)} invalid AD import task definition(s):")
        for item_content, errors, source_info in invalid_ad_import_details:
            logger.error(f"  Invalid task from {source_info}: '{str(item_content)[:100]}...' -> Errors: {errors}")

    normalized_ad_import_tasks: List[Dict] = []
    for raw_task_dict in valid_raw_ad_imports:
        group_name = raw_task_dict['group_name'] 
        role = raw_task_dict.get('role') or constants.DEFAULT_AD_IMPORT_ROLE
        if not raw_task_dict.get('role'):
            logger.debug(f"Using default role '{role}' for AD group '{group_name}'.")
        
        # Use 'Scope' from input task as per constants.AD_IMPORT_TASK_OPTIONAL_KEYS
        # process_ad_import_task expects 'scope_name' in its input dict.
        current_scope_val = raw_task_dict.get('scope') 
        
        normalized_task = {
            "group_name": group_name,
            "role_name": role,
            "scope_name": current_scope_val # Pass the value of 'Scope' as 'scope_name'
        }
        normalized_ad_import_tasks.append(normalized_task)
        logger.debug(f"Normalized AD import task: {normalized_task}")

    if not normalized_ad_import_tasks and (total_cli_tasks + total_config_tasks) > 0 : # Had inputs, but none were valid
        logger.warning("No valid AD import tasks to process after validation. Exiting.")
        sys.exit(0) 
    elif not normalized_ad_import_tasks: # No inputs and no valid tasks (already logged above if no tasks defined)
        pass # Proceed to logout if no tasks were ever defined or processed

    exit_code = 0
    if normalized_ad_import_tasks: # Only run workflow if there are tasks
        try:
            workflow_success = run_ad_import_workflow(
                ome_client_instance,
                ad_provider_id, # type: ignore 
                ad_provider_name_for_logging, # type: ignore
                ad_search_username_val, # type: ignore
                ad_search_password_val, # type: ignore
                normalized_ad_import_tasks,
                logger
            )
            if not workflow_success:
                logger.warning("AD import workflow completed with one or more task-level errors.")
                # exit_code = 1 # Optionally set exit code if any task fails
        except Exception as e:
            logger.fatal(f"Core AD import workflow failed unexpectedly: {e}", exc_info=True)
            exit_code = 1
    
    if ome_client_instance:
        try:
            ome_client_instance.logout()
        except Exception as e:
            logger.warning(f"Error during OME logout: {e}", exc_info=args.debug)
            
    logger.info(f"OME AD Group Import script finished with exit code {exit_code}.")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
