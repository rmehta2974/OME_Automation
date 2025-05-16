#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OME AD Group Import Manager script (v3.1.11).
Imports AD groups via OME provider, assigns roles (with default), adds scope.
Uses 'role' and 'scope' as input keys for AD import tasks.
"""

# __version__ = "3.1.10" # Previous version
__version__ = "3.1.11" # Aligned AD import task keys to 'role' and 'scope'.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-15 | 3.1.10  | Gemini     | Updated call to input_validator to use
#            |         |            | validate_ad_search_credentials_and_provider_name_specific
# 2025-05-15 | 3.1.11  | Gemini     | Changed AD import task handling to use 'role' and 'scope' keys
#            |         |            | consistently for normalization and processing.

import argparse
import sys
import logging
import json 
from typing import Dict, List, Optional, Tuple, Any 

import utils 
import constants # Expecting v1.3.9 or later
import input_validator # Expecting v1.2.10 or later
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
                           normalized_ad_import_tasks: List[Dict], # Expects tasks to have 'role' and 'scope' keys
                           logger_instance: logging.Logger) -> bool: 
    logger_instance.info(f"Starting processing of {len(normalized_ad_import_tasks)} AD group import task(s) using AD Provider '{ad_provider_name_for_logging}' (ID: {ad_provider_id})...")
    if not normalized_ad_import_tasks:
        logger_instance.info("No AD import tasks to process.")
        return True 

    overall_success = True
    for import_task in normalized_ad_import_tasks:
        # process_ad_import_task now expects 'role' and 'scope' in import_task
        if not process_ad_import_task(
            ome_client_instance,
            ad_provider_id,
            ad_search_username,
            ad_search_password,
            import_task, # This dict should have 'role' and 'scope'
            logger_instance 
        ):
            overall_success = False # Mark if any individual task processing fails

    if not overall_success:
        logger_instance.warning("One or more AD import tasks encountered errors during processing.")
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
                           import_task: Dict, # Expects 'role' and 'scope' keys
                           logger: logging.Logger) -> bool: # Return bool for success/failure 
    ad_group_name = import_task.get('group_name')
    # Use 'role' key from import_task, defaulting to constants.DEFAULT_AD_IMPORT_ROLE
    role_to_assign = import_task.get('role', constants.DEFAULT_AD_IMPORT_ROLE)
    # Use 'scope' key from import_task
    raw_scope_input = import_task.get('scope')

    logger.info(f"--- Processing AD group import: '{ad_group_name}' ---")
    logger.debug(f"Task Details: AD Group='{ad_group_name}', Role='{role_to_assign}', Scope='{raw_scope_input or 'None'}'")

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
            logger.error(f"AD group '{ad_group_name}' not found via OME search or ObjectGuid missing. Task failed.")
            return False # Task failed

        logger.debug(f"Finding OME Role ID for role name '{role_to_assign}'...")
        ome_role_id_raw = ome_client_instance.get_role_id_by_name(role_to_assign)
        if ome_role_id_raw:
            ome_role_id = str(ome_role_id_raw)
            logger.info(f"Found OME Role ID for '{role_to_assign}': {ome_role_id}")
        else:
            logger.error(f"OME Role '{role_to_assign}' not found. Task failed for AD group '{ad_group_name}'.")
            return False # Task failed

        logger.info(f"Checking if OME Account with UserName '{ad_group_name}' already exists...")
        existing_ome_account = ome_client_instance.get_imported_ad_account_by_username(ad_group_name)
        if existing_ome_account:
            existing_ome_account_id_raw = existing_ome_account.get('Id')
            if existing_ome_account_id_raw is not None:
                imported_ome_account_id_str = str(existing_ome_account_id_raw)
                found_object_guid_on_ome = existing_ome_account.get('ObjectGuid', 'NOT_FOUND_ON_OME_ACCOUNT')
                logger.warning(f"OME Account with UserName '{ad_group_name}' already exists (ID: {imported_ome_account_id_str}). Its ObjectGuid on OME: '{found_object_guid_on_ome}'. Searched AD group ObjectGuid: '{ad_object_guid}'. Skipping import, will proceed to scope assignment.")
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
                    logger.error(f"AD group import for '{ad_group_name}' failed or returned no OME Account ID. Task failed.")
                    return False # Task failed
            except Exception as e: 
                logger.error(f"Error during AD group import for '{ad_group_name}': {e}. Task failed.", exc_info=logger.isEnabledFor(logging.DEBUG))
                return False # Task failed

        # Scope handling
        individual_scope_names_to_process: List[str] = []
        if isinstance(raw_scope_input, list):
            for item in raw_scope_input:
                if isinstance(item, str) and item.strip():
                    individual_scope_names_to_process.append(item.strip())
        elif isinstance(raw_scope_input, str) and raw_scope_input.strip():
            if ',' in raw_scope_input:
                individual_scope_names_to_process.extend([s.strip() for s in raw_scope_input.split(',') if s.strip()])
            else:
                individual_scope_names_to_process.append(raw_scope_input.strip())
        
        if imported_ome_account_id_str and raw_scope_input is not None: # If scope was intended
            if individual_scope_names_to_process:
                collected_scope_group_ids_as_str: List[str] = []
                for s_name_to_find in individual_scope_names_to_process:
                    scope_group_details = ome_client_instance.get_group_by_name(s_name_to_find)
                    if scope_group_details and scope_group_details.get('Id') is not None:
                        scope_group_id_str = str(scope_group_details.get('Id'))
                        if scope_group_id_str.strip():
                            collected_scope_group_ids_as_str.append(scope_group_id_str)
                            logger.info(f"Found scope group '{s_name_to_find}' (ID: {scope_group_id_str}) for AD group '{ad_group_name}'.")
                        else:
                            logger.warning(f"Scope group '{s_name_to_find}' for AD group '{ad_group_name}' found but its ID is empty.")
                    else:
                        logger.warning(f"Scope group ('{s_name_to_find}') for AD group '{ad_group_name}' not found or its ID is missing.")
                
                try:
                    logger.info(f"Setting/updating scopes for OME Account ID {imported_ome_account_id_str} to group IDs: {collected_scope_group_ids_as_str}")
                    ome_client_instance.add_scope_to_ad_group(imported_ome_account_id_str, collected_scope_group_ids_as_str)
                    logger.info(f"Call to set scopes for OME Account ID {imported_ome_account_id_str} completed.")
                except Exception as e:
                    logger.error(f"Error setting scopes for OME Account '{imported_ome_account_id_str}': {e}", exc_info=logger.isEnabledFor(logging.DEBUG))
                    # Decide if scope failure means task failure. For now, just logging.
            else: # raw_scope_input was provided but parsed to nothing (e.g. empty string, or list of empty strings)
                logger.info(f"Scope input for '{ad_group_name}' was present but yielded no valid scope names. To clear scopes, provide an empty list to the OME API if supported by add_scope_to_ad_group, or ensure input is truly empty/None if no change is desired.")
                # If intent is to clear scopes, call with empty list:
                # ome_client_instance.add_scope_to_ad_group(imported_ome_account_id_str, [])

        elif imported_ome_account_id_str and raw_scope_input is None:
            logger.info(f"No 'scope' provided in the import task for AD group '{ad_group_name}'. Existing scopes will remain unchanged.")
        
        logger.info(f"--- Successfully processed AD group import for '{ad_group_name}' ---")
        return True # Task succeeded

    except Exception as e: 
        logger.error(f"Unexpected error processing task for AD group '{ad_group_name}': {e}", exc_info=True)
        return False # Task failed
    # finally: # Removed finally block as return statements handle exit
        # logger.info(f"--- Finished processing AD group import for '{ad_group_name}' ---")


#------------------------------------------------------------------------------
# Main execution block
#------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Import AD groups into OME using a pre-configured AD Provider.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    grp_ome = parser.add_argument_group('OME Connection Details')
    grp_ome.add_argument('--ome-url', metavar='URL')
    grp_ome.add_argument('--username', metavar='USER')
    grp_ome.add_argument('--password', metavar='PASS')

    grp_ad = parser.add_argument_group('AD Provider & Credentials')
    grp_ad.add_argument('--ad-name', dest='ad_name', help="Name of the pre-configured AD provider in OME", metavar='PROVIDER_NAME')
    grp_ad.add_argument('--ad-username', dest='ad_username', help="Username for AD (for searching groups via OME)", metavar='AD_USER')
    grp_ad.add_argument('--ad-password', dest='ad_password', help="Password for AD (for searching groups via OME)", metavar='AD_PASS')

    grp_input = parser.add_argument_group('Input Sources for AD Group Import Tasks')
    grp_input.add_argument('--config', help='Path to JSON config file', metavar='FILE_PATH')
    # Help text updated for 'role' and 'scope'
    ad_group_task_help = (
        f"JSON for AD import task. Keys: 'group_name' (req), 'role' (opt, def: {constants.DEFAULT_AD_IMPORT_ROLE}), 'scope' (opt, string or list of strings)."
    )
    grp_input.add_argument(
        f'--{constants.AD_IMPORT_GROUP_CLI_ARG_NAME}', # 'adgroup'
        action='append',
        help=ad_group_task_help,
        metavar='JSON_STRING'
    )

    grp_log = parser.add_argument_group('Logging Options')
    grp_log.add_argument('--debug', action='store_true')
    grp_log.add_argument('--log-file', metavar='LOG_FILE_PATH')
    args = parser.parse_args()

    utils.setup_logger(debug=args.debug, log_file_path=args.log_file)
    logger.info(f"OME AD Group Import script started (Version: {__version__}).")
    logger.debug(f"Parsed arguments: {args}")

    config: Optional[Dict] = None
    if args.config:
        config = utils.load_config(args.config, logger)
        if config is None:
            logger.fatal(f"Failed config load from '{args.config}'. Exiting.")
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
        ome_client_instance = ome_client.OmeClient(
            ome_creds['url'], ome_creds['username'], ome_creds['password']
        )
        ome_client_instance.authenticate()
        logger.info("Successfully authenticated with OME.")
    except Exception as e:
        logger.fatal(f"Failed OME client setup/auth: {e}", exc_info=args.debug)
        sys.exit(1)

    ad_provider_id: Optional[int] = None
    ad_provider_name_for_logging: Optional[str] = None
    ad_search_username_val: Optional[str] = None
    ad_search_password_val: Optional[str] = None
    try:
        ad_config_data, is_ad_config_valid = utils.collect_and_validate_credentials(
            args, config,
            constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.union(constants.AD_CRED_REQUIRED_KEYS),
            constants.AD_CONFIG_SECTION, 
            constants.AD_CONFIG_CLI_MAP, 
            input_validator.validate_ad_search_credentials_and_provider_name_specific, 
            logger
        )
        if not is_ad_config_valid:
            logger.fatal("Invalid or missing AD Provider Name and/or AD Search Credentials. Exiting.")
            sys.exit(1)

        ad_provider_name_for_logging = ad_config_data.get('Name')
        ad_search_username_val = ad_config_data.get('UserName') # Changed from Username to UserName
        ad_search_password_val = ad_config_data.get('Password')
        
        if not ad_provider_name_for_logging: 
            logger.fatal("AD Provider Name missing. Exiting.")
            sys.exit(1)
        if ad_search_username_val is None or ad_search_password_val is None: 
             logger.fatal("AD search username or password missing. Exiting.")
             sys.exit(1)

        logger.info(f"Finding OME ID for AD Provider '{ad_provider_name_for_logging}'...")
        ad_provider_id_raw = ome_client_instance.get_ad_provider_id_by_name(ad_provider_name_for_logging)
        if ad_provider_id_raw is None:
            logger.fatal(f"AD Provider '{ad_provider_name_for_logging}' not found or no ID. Exiting.")
            sys.exit(1)
        try:
            ad_provider_id = int(ad_provider_id_raw)
        except ValueError:
            logger.fatal(f"AD Provider ID '{ad_provider_id_raw}' for '{ad_provider_name_for_logging}' not valid int. Exiting.")
            sys.exit(1)
        logger.info(f"Using AD Provider ID: {ad_provider_id} for '{ad_provider_name_for_logging}'.")

    except Exception as e:
        logger.fatal(f"Error handling AD provider/credentials: {e}", exc_info=args.debug)
        sys.exit(1)

    valid_raw_ad_imports, invalid_ad_import_details = utils.collect_and_validate_list_inputs(
        args, config,
        constants.AD_IMPORT_GROUP_CLI_ARG_NAME, 
        constants.AD_IMPORT_GROUP_CONFIG_SECTION, 
        input_validator.validate_ad_import_task_specific, # This validator now expects 'role' and 'scope'
        logger
    )
    
    cli_ad_tasks_value = getattr(args, constants.AD_IMPORT_GROUP_CLI_ARG_NAME, None)
    total_cli_tasks = len(cli_ad_tasks_value) if cli_ad_tasks_value is not None else 0
    config_ad_tasks_list = utils.get_config_section(config, constants.AD_IMPORT_GROUP_CONFIG_SECTION, [])
    total_config_tasks = len(config_ad_tasks_list) if isinstance(config_ad_tasks_list, list) else 0
    
    if (total_cli_tasks + total_config_tasks) == 0:
        logger.info("No AD import tasks defined. Nothing to do for AD import.")
    elif (total_cli_tasks + total_config_tasks) == 1 and not valid_raw_ad_imports:
        logger.fatal("Single AD import task provided, and it is invalid. Exiting.")
        sys.exit(1)

    if invalid_ad_import_details:
        logger.warning(f"Skipping {len(invalid_ad_import_details)} invalid AD import task definition(s):")
        for item_content, errors, source_info in invalid_ad_import_details:
            logger.error(f"  Invalid task from {source_info}: '{str(item_content)[:100]}...' -> Errors: {errors}")

    normalized_ad_import_tasks: List[Dict] = []
    for raw_task_dict in valid_raw_ad_imports:
        group_name = raw_task_dict['group_name'] 
        # Normalize to 'role' and 'scope' for process_ad_import_task
        role_val = raw_task_dict.get('role', constants.DEFAULT_AD_IMPORT_ROLE) # Get 'role'
        if 'role' not in raw_task_dict: # Log if default was applied because key was missing
            logger.debug(f"Using default role '{role_val}' for group '{group_name}' as 'role' key was not specified.")
        
        scope_val = raw_task_dict.get('scope') # Get 'scope'
        
        normalized_task = {
            "group_name": group_name,
            "role": role_val,    # Store as 'role'
            "scope": scope_val   # Store as 'scope'
        }
        normalized_ad_import_tasks.append(normalized_task)
        logger.debug(f"Normalized AD import task: {normalized_task}")

    if not normalized_ad_import_tasks and (total_cli_tasks + total_config_tasks) > 0 :
        logger.warning("No valid AD import tasks to process after validation. Exiting.")
        sys.exit(0) 
    
    exit_code = 0
    if normalized_ad_import_tasks: 
        try:
            workflow_success = run_ad_import_workflow(
                ome_client_instance,
                ad_provider_id, 
                ad_provider_name_for_logging, 
                ad_search_username_val, 
                ad_search_password_val, 
                normalized_ad_import_tasks,
                logger
            )
            if not workflow_success:
                logger.warning("AD import workflow completed with one or more task-level errors.")
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
