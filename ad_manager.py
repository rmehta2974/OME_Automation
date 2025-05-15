#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OME AD Group Import Manager script (v3.1.8).
Imports AD groups via OME provider, assigns roles (with default), adds scope.
Requires AD credentials for searching groups via OME.
Checks for existing OME account by UserName before import.
Handles various scope_name input formats (None, string, list, comma-separated string).
"""

# __version__ = "3.1.7" # Previous version
__version__ = "3.1.8" # Integrated advanced scope handling in process_ad_import_task

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-15 | 3.1.6   | Gemini     | Aligned with ome_client changes for AD search payload (UserName) and GUID field (ObjectGuid).
# 2025-05-15 | 3.1.7   | Gemini     | Updated process_ad_import_task to use get_imported_ad_account_by_username for pre-check.
#            |         |            | Ensured import_ad_group is called with new payload structure (list of dict).
# 2025-05-15 | 3.1.8   | Gemini     | Replaced process_ad_import_task with version from canvas "ad_import_processor_updated",
#            |         |            | which includes robust parsing for 'scope_name' (None, string, list, comma-separated)
#            |         |            | and calls add_scope_to_ad_group with a list of string IDs.

import argparse
import sys
import logging
import json # Retained even if not directly used in this version of process_ad_import_task, for general utility.
# requests.exceptions is not directly used here but might be in ome_client or utils.
# from requests.exceptions import ConnectionError, HTTPError, Timeout # Example if needed directly

from typing import Dict, List, Optional, Tuple, Any # Ensure Tuple and Any are needed or remove

# Ensure these custom modules are available in the Python path and are the correct versions
import utils # Ensure this is v1.0.4 or later
import constants # Ensure this is constants_v1_2_3_final or later
import input_validator # Ensure this is input_validator_v1_2_2_final or later
import ome_client # Ensure this is ome_client_v1_10_23 or later (or version compatible with add_scope_to_ad_group(str, List[str]))

# Initialize logger for this module
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
                           logger_instance: logging.Logger) -> bool: # Renamed param to avoid conflict with module logger
    """
    Manages the overall workflow for importing multiple AD groups.
    Iterates through each normalized task and calls process_ad_import_task.
    """
    logger_instance.info(f"Starting processing of {len(normalized_ad_import_tasks)} AD group import task(s) using AD Provider '{ad_provider_name_for_logging}' (ID: {ad_provider_id})...")
    if not normalized_ad_import_tasks:
        logger_instance.info("No AD import tasks to process.")
        return True # Considered successful as there's nothing to fail on

    overall_success = True
    for import_task in normalized_ad_import_tasks:
        try:
            # Call the detailed task processing function
            process_ad_import_task(
                ome_client_instance,
                ad_provider_id,
                ad_search_username,
                ad_search_password,
                import_task,
                logger_instance # Pass the specific logger instance
            )
        except Exception as e:
            # Catch unexpected errors from process_ad_import_task itself, though it should handle its own.
            group_name_for_error = import_task.get('group_name', 'Unknown Task')
            logger_instance.error(f"Unexpected critical error during workflow for AD import task '{group_name_for_error}': {e}", exc_info=True)
            overall_success = False # Mark the workflow as having encountered issues

    if not overall_success:
        logger_instance.warning("One or more AD import tasks encountered unexpected critical errors during the workflow.")
    else:
        logger_instance.info("Finished processing all AD group import tasks.")
    return overall_success

#------------------------------------------------------------------------------
# Task Processing Function (Replaced with the version from Canvas)
#------------------------------------------------------------------------------
def process_ad_import_task(ome_client_instance: ome_client.OmeClient, # Use quotes if OmeClient is not fully defined here
                           ad_provider_id: int,
                           ad_search_username: str,
                           ad_search_password: str,
                           import_task: Dict,
                           logger: logging.Logger): # Parameter name is 'logger' here
    """
    Processes an AD group import task, including finding the AD group,
    importing it if necessary, and then setting its scope in OME
    based on the provided scope_name(s).
    """
    ad_group_name = import_task.get('group_name')
    # Fallback to a default role if not specified in the task
    role_name = import_task.get('role_name', constants.DEFAULT_AD_IMPORT_ROLE)
    # raw_scope_input can be None, a string (single scope or comma-separated), or a list of strings
    raw_scope_input = import_task.get('scope_name')

    logger.info(f"--- Processing AD group import: '{ad_group_name}' ---")
    logger.debug(f"Task Details: AD Group='{ad_group_name}', Role='{role_name}', Raw Scope Input='{raw_scope_input or 'None'}'")

    ad_object_guid: Optional[str] = None
    ome_role_id: Optional[str] = None
    # This will store the OME Account ID as a string, as returned by the API or found
    imported_ome_account_id_str: Optional[str] = None

    try:
        # Step 1: Find the AD group in AD via OME to get its ObjectGuid
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

        # Step 2: Find the OME Role ID for the specified role name
        logger.debug(f"Finding OME Role ID for role name '{role_name}'...")
        ome_role_id_raw = ome_client_instance.get_role_id_by_name(role_name)
        if ome_role_id_raw:
            ome_role_id = str(ome_role_id_raw) # Ensure it's a string
            logger.info(f"Found OME Role ID for '{role_name}': {ome_role_id}")
        else:
            logger.error(f"OME Role '{role_name}' not found. Skipping task for AD group '{ad_group_name}'.")
            return

        # Step 3: Check if an OME Account (imported AD group) already exists by its UserName
        logger.info(f"Checking if OME Account with UserName '{ad_group_name}' already exists...")
        existing_ome_account = ome_client_instance.get_imported_ad_account_by_username(ad_group_name)
        if existing_ome_account:
            existing_ome_account_id_raw = existing_ome_account.get('Id')
            if existing_ome_account_id_raw is not None:
                imported_ome_account_id_str = str(existing_ome_account_id_raw) # Store as string
                found_object_guid_on_ome = existing_ome_account.get('ObjectGuid', 'NOT_FOUND_ON_OME_ACCOUNT')
                logger.warning(f"OME Account with UserName '{ad_group_name}' already exists (ID: {imported_ome_account_id_str}). Its ObjectGuid on OME: '{found_object_guid_on_ome}'. Searched AD group ObjectGuid: '{ad_object_guid}'. Skipping import, will proceed to scope assignment if applicable.")
            else:
                # Account found by name but has no ID - unusual, but attempt import as a fallback
                logger.warning(f"OME Account with UserName '{ad_group_name}' found but its OME Account ID is missing. Attempting fresh import as a precaution.")
        else:
            logger.info(f"OME Account with UserName '{ad_group_name}' not found. Will proceed with import.")

        # Step 4: If no existing OME account was found (or it was problematic), import the AD group
        if not imported_ome_account_id_str:
            logger.info(f"Attempting to import AD group '{ad_group_name}' (ObjectGuid: {ad_object_guid}) as user with Role ID {ome_role_id}...")
            try:
                # Ensure import_ad_group arguments match its definition
                import_result_id = ome_client_instance.import_ad_group(
                    ad_provider_id, ad_group_name, ad_object_guid, ome_role_id # type: ignore
                )
                if import_result_id:
                    imported_ome_account_id_str = str(import_result_id) # Store as string
                    logger.info(f"AD group '{ad_group_name}' imported as user. New OME Account ID: {imported_ome_account_id_str}")
                else:
                    logger.error(f"AD group import for '{ad_group_name}' failed or returned no OME Account ID. Skipping scope assignment.")
                    return
            except Exception as e:
                logger.error(f"Error during AD group import for '{ad_group_name}': {e}. Skipping scope assignment.", exc_info=logger.isEnabledFor(logging.DEBUG))
                return

        # --- SCOPE HANDLING LOGIC START ---
        # This list will hold the individual scope names parsed from the input
        individual_scope_names_to_process: List[str] = []

        # Parse the raw_scope_input (which can be None, string, or list of strings)
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
            elif ',' in raw_scope_input_stripped:  # Handles comma-separated string of scope names
                names = [s.strip() for s in raw_scope_input_stripped.split(',') if s.strip()]
                if names:
                    individual_scope_names_to_process.extend(names)
                else: # e.g. raw_scope_input was just "," or ", , "
                    logger.warning(f"Comma-separated scope string '{raw_scope_input_stripped}' for AD group '{ad_group_name}' resulted in no valid scope names after parsing.")
            else:  # Single scope name as a string
                individual_scope_names_to_process.append(raw_scope_input_stripped)
        elif raw_scope_input is not None:  # Fallback for unexpected but non-None types
            logger.warning(f"Unexpected type for scope_name: {type(raw_scope_input)} for AD group '{ad_group_name}'. Attempting to treat as string.")
            try:
                fallback_str_scope = str(raw_scope_input).strip()
                if fallback_str_scope:
                    if ',' in fallback_str_scope: # Check again for comma-separated in fallback
                        names = [s.strip() for s in fallback_str_scope.split(',') if s.strip()]
                        if names: individual_scope_names_to_process.extend(names)
                    else:
                        individual_scope_names_to_process.append(fallback_str_scope)
                else:
                    logger.warning(f"Fallback conversion of scope value '{raw_scope_input}' for AD group '{ad_group_name}' resulted in an empty string.")
            except Exception as e:
                logger.error(f"Could not convert unexpected scope type '{type(raw_scope_input)}' to string for AD group '{ad_group_name}': {e}")

        # Proceed with scope assignment if an OME account ID exists
        # AND if scope_name was provided in the import task (raw_scope_input is not None).
        # This means if scope_name is omitted, existing scopes are not touched.
        # If scope_name is present (even if empty string or list), it signals intent to manage scopes.
        if imported_ome_account_id_str and raw_scope_input is not None:
            logger.info(f"Attempting to set scopes for OME Account ID: {imported_ome_account_id_str} (AD Group: '{ad_group_name}') based on requested scope name(s).")
            
            # This list will hold the string IDs of the resolved scope groups
            collected_scope_group_ids_as_str: List[str] = []

            if individual_scope_names_to_process: # Only try to find IDs if there are names to look for
                for s_name_to_find in individual_scope_names_to_process:
                    logger.debug(f"Searching for OME static group (scope) '{s_name_to_find}' to get its ID...")
                    scope_group_details = ome_client_instance.get_group_by_name(s_name_to_find)
                    if scope_group_details and scope_group_details.get('Id') is not None:
                        scope_group_id_str = str(scope_group_details.get('Id')) # Keep as string
                        # Basic validation: ensure it's not an empty string if API returns such
                        if scope_group_id_str.strip():
                            collected_scope_group_ids_as_str.append(scope_group_id_str)
                            logger.info(f"Found OME static group (scope) '{s_name_to_find}' with ID: {scope_group_id_str}.")
                        else:
                            logger.warning(f"OME static group (scope) '{s_name_to_find}' found but its ID is empty. Skipping this scope.")
                    else:
                        logger.warning(f"OME static group (scope) ('{s_name_to_find}') not found or its ID is missing. This scope will not be included.")
            
            # Now, call the OME client method to set/update the scopes.
            # The add_scope_to_ad_group method expects a string account ID and a list of string group IDs.
            # It will handle the conversion to integers for the payload internally.
            # If collected_scope_group_ids_as_str is empty (e.g., raw_scope_input was "" or [] or names didn't resolve),
            # your OmeClient.add_scope_to_ad_group handles this by logging and returning,
            # effectively not changing scopes if no valid new scopes are specified.
            try:
                logger.info(f"Calling 'add_scope_to_ad_group' for OME Account ID {imported_ome_account_id_str} with resolved static group IDs: {collected_scope_group_ids_as_str}")
                ome_client_instance.add_scope_to_ad_group(
                    imported_ome_account_id_str, # This is already a string
                    collected_scope_group_ids_as_str  # This is List[str]
                ) # type: ignore
                # Logging of success/failure is handled within add_scope_to_ad_group or by exceptions
                logger.info(f"Call to 'add_scope_to_ad_group' completed for OME Account ID {imported_ome_account_id_str}.")

            except Exception as e:
                # Errors from add_scope_to_ad_group (like ValueError for bad IDs or API errors) will be caught here if re-raised.
                # The method itself also logs errors.
                logger.error(f"Error occurred during the call to 'add_scope_to_ad_group' for OME Account ID {imported_ome_account_id_str}: {e}", exc_info=logger.isEnabledFor(logging.DEBUG))

        elif imported_ome_account_id_str and raw_scope_input is None:
            # This case means an account ID exists, but no 'scope_name' was provided in the task.
            # So, we intentionally do not modify existing scopes.
            logger.info(f"No 'scope_name' provided in the import task for AD group '{ad_group_name}' (OME Account ID: {imported_ome_account_id_str}). Existing scopes will remain unchanged.")
        elif not imported_ome_account_id_str and raw_scope_input is not None:
            # This case means scopes were requested, but we couldn't get/create an OME Account ID.
            logger.warning(f"Cannot process scopes (input: '{raw_scope_input}') because OME Account ID for AD group '{ad_group_name}' could not be determined.")
        # --- SCOPE HANDLING LOGIC END ---

    except Exception as e:
        # Catch-all for any other unexpected errors during the task processing
        logger.error(f"Unexpected error processing task for AD group '{ad_group_name}': {e}", exc_info=True)
    finally:
        logger.info(f"--- Finished processing AD group import for '{ad_group_name}' ---")

#------------------------------------------------------------------------------
# Main execution block
#------------------------------------------------------------------------------
def main():
    """
    Main function to parse arguments, set up logging, authenticate,
    and orchestrate the AD group import workflow.
    """
    # Argument parsing setup
    parser = argparse.ArgumentParser(
        description="Import AD groups into OME using a pre-configured AD Provider.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # OME Connection Details Group
    grp_ome = parser.add_argument_group('OME Connection Details')
    grp_ome.add_argument('--ome-url', metavar='URL', help="URL for the OME instance (e.g., https://ome.example.com)")
    grp_ome.add_argument('--username', metavar='USER', help="OME username for authentication")
    grp_ome.add_argument('--password', metavar='PASS', help="OME password for authentication")

    # AD Provider & Credentials Group
    grp_ad = parser.add_argument_group('AD Provider & Credentials')
    grp_ad.add_argument('--ad-name', dest='ad_name', help="Name of the pre-configured AD provider in OME", metavar='PROVIDER_NAME')
    grp_ad.add_argument('--ad-username', dest='ad_username', help="Username for AD (for searching groups via OME)", metavar='AD_USER')
    grp_ad.add_argument('--ad-password', dest='ad_password', help="Password for AD (for searching groups via OME)", metavar='AD_PASS')

    # Input Sources Group
    grp_input = parser.add_argument_group('Input Sources for AD Group Import Tasks')
    grp_input.add_argument('--config', help='Path to JSON config file containing connection details and/or import tasks', metavar='FILE_PATH')
    # Dynamically create help text for --ad-group-task to show the default role
    ad_group_task_help = (
        f"JSON string for a single AD import task. Keys: 'group_name' (required), "
        f"'role_name' (optional, default: {constants.DEFAULT_AD_IMPORT_ROLE}), "
        f"'scope_name' (optional, can be string or list of strings). Can be used multiple times."
    )
    grp_input.add_argument(
        f'--{constants.AD_IMPORT_GROUP_CLI_ARG_NAME}',
        action='append', # Allows multiple instances of this argument
        help=ad_group_task_help,
        metavar='JSON_STRING'
    )

    # Logging Options Group
    grp_log = parser.add_argument_group('Logging Options')
    grp_log.add_argument('--debug', action='store_true', help="Enable debug level logging")
    grp_log.add_argument('--log-file', metavar='LOG_FILE_PATH', help="Path to a file for logging output")
    args = parser.parse_args()

    # Setup logger (using the global logger initialized at the top of the script)
    utils.setup_logger(logger_to_configure=logger, debug=args.debug, log_file_path=args.log_file) # Pass the module logger
    logger.info(f"OME AD Group Import script started (Version: {__version__}).")
    logger.debug(f"Parsed arguments: {args}")

    # Load configuration from file if --config is provided
    config: Optional[Dict] = None
    if args.config:
        config = utils.load_config(args.config, logger) # Pass logger
        if config is None:
            logger.fatal(f"Failed to load configuration from '{args.config}'. Exiting.")
            sys.exit(1)

    # Collect and validate OME credentials
    ome_creds, is_ome_creds_valid = utils.collect_and_validate_credentials(
        args, config, constants.OME_AUTH_REQUIRED_KEYS,
        constants.OME_CRED_CONFIG_SECTION, constants.OME_CLI_CRED_MAP,
        input_validator.validate_ome_credentials_specific, logger # Pass logger
    )
    if not is_ome_creds_valid:
        logger.fatal("Invalid or missing OME credentials. Exiting.")
        sys.exit(1)

    # Initialize and authenticate OME client
    ome_client_instance: Optional[ome_client.OmeClient] = None
    try:
        logger.debug(f"Initializing OME client for URL: {ome_creds.get('url')}")
        ome_client_instance = ome_client.OmeClient(
            ome_creds['url'], ome_creds['username'], ome_creds['password'], logger_instance=logger # Pass logger
        )
        ome_client_instance.authenticate()
        logger.info("Successfully authenticated with OME.")
    except Exception as e:
        logger.fatal(f"Failed OME client setup or authentication: {e}", exc_info=args.debug)
        sys.exit(1)

    # Collect and validate AD Provider details and search credentials
    ad_provider_id: Optional[int] = None
    ad_provider_name_for_logging: Optional[str] = None
    ad_search_username_val: Optional[str] = None # Renamed to avoid conflict
    ad_search_password_val: Optional[str] = None # Renamed to avoid conflict
    try:
        ad_config, is_ad_config_valid = utils.collect_and_validate_credentials(
            args, config,
            constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND.union(constants.AD_CRED_REQUIRED_KEYS),
            constants.AD_CONFIG_SECTION,
            constants.AD_CONFIG_CLI_MAP,
            input_validator.validate_ad_search_credentials_specific,
            logger # Pass logger
        )
        if not is_ad_config_valid:
            logger.fatal("Invalid or missing AD Provider Name and/or AD Search Credentials. Exiting.")
            sys.exit(1)

        ad_provider_name_for_logging = ad_config.get('Name') # 'Name' from constants.AD_PROVIDER_REQUIRED_KEYS_FOR_FIND
        ad_search_username_val = ad_config.get('Username')   # 'Username' from constants.AD_CRED_REQUIRED_KEYS
        ad_search_password_val = ad_config.get('Password')   # 'Password' from constants.AD_CRED_REQUIRED_KEYS
        
        if not ad_provider_name_for_logging: # Should be caught by validator, but defensive check
            logger.fatal("AD Provider Name is missing after validation. Cannot proceed. Exiting.")
            sys.exit(1)
        if ad_search_username_val is None or ad_search_password_val is None: # Defensive
             logger.fatal("AD search username or password missing after validation. Exiting.")
             sys.exit(1)


        logger.info(f"Finding OME ID for AD Provider '{ad_provider_name_for_logging}'...")
        ad_provider_id_raw = ome_client_instance.get_ad_provider_id_by_name(ad_provider_name_for_logging)
        if ad_provider_id_raw is None: # API might return None or an empty value
            logger.fatal(f"AD Provider '{ad_provider_name_for_logging}' not found or has no ID in OME. Exiting.")
            sys.exit(1)
        try:
            ad_provider_id = int(ad_provider_id_raw) # Ensure it's an integer
        except ValueError:
            logger.fatal(f"AD Provider ID '{ad_provider_id_raw}' for '{ad_provider_name_for_logging}' is not a valid integer. Exiting.")
            sys.exit(1)
        logger.info(f"Using AD Provider ID: {ad_provider_id} for '{ad_provider_name_for_logging}'.")

    except Exception as e:
        logger.fatal(f"Error handling AD provider configuration or credentials: {e}", exc_info=args.debug)
        sys.exit(1)

    # Collect and validate AD group import tasks from CLI arguments and config file
    valid_raw_ad_imports, invalid_ad_import_details = utils.collect_and_validate_list_inputs(
        args, config,
        constants.AD_IMPORT_GROUP_CLI_ARG_NAME,
        constants.AD_IMPORT_GROUP_CONFIG_SECTION,
        input_validator.validate_ad_import_task_specific, # Validator for individual tasks
        logger # Pass logger
    )

    # Log invalid tasks that were skipped
    if invalid_ad_import_details:
        logger.warning(f"Skipping {len(invalid_ad_import_details)} invalid AD import task definition(s):")
        for item_content, errors, source_info in invalid_ad_import_details:
            logger.error(f"  Invalid task from {source_info}: '{str(item_content)[:100]}...' -> Errors: {errors}")

    # Normalize valid tasks (e.g., ensure default role, correct key names)
    normalized_ad_import_tasks: List[Dict] = []
    for raw_task_dict in valid_raw_ad_imports:
        # Ensure 'group_name' is present (should be guaranteed by validator)
        group_name = raw_task_dict['group_name'] # Access directly if validator ensures presence
        
        # Set default role if 'role_name' is not provided or is empty
        role = raw_task_dict.get('role_name') or constants.DEFAULT_AD_IMPORT_ROLE
        if not raw_task_dict.get('role_name'): # Log if default was applied
            logger.debug(f"Using default role '{role}' for AD group '{group_name}' as no role_name was specified.")
        
        # Get 'scope_name' (can be None, string, or list). Key in config/CLI might be 'Scope' or 'scope_name'.
        # Assuming validator/collector normalizes it to 'scope_name' or we use a consistent key like 'Scope' from constants.
        # The example normalization used 'Scope'. Let's stick to 'scope_name' for internal consistency if possible.
        # The current process_ad_import_task expects 'scope_name'.
        # The example in main() for CLI arg help text uses 'Scope'.
        # Let's assume utils.collect_and_validate_list_inputs or the validator handles this,
        # or we adjust the key here. For now, assuming 'scope_name' is the target key.
        # If 'Scope' is used in input, it needs to be mapped to 'scope_name'.
        # The provided `normalized_ad_import_tasks.append` uses `raw_task_dict.get('Scope')`
        # so `process_ad_import_task` should get it via `import_task.get('scope_name')`
        # This means the key in `normalized_ad_import_tasks` MUST be 'scope_name'.
        
        current_scope_val = raw_task_dict.get('scope_name', raw_task_dict.get('Scope')) # Try both common keys

        normalized_task = {
            "group_name": group_name,
            "role_name": role,
            "scope_name": current_scope_val # This will be None if neither key was present
        }
        normalized_ad_import_tasks.append(normalized_task)
        logger.debug(f"Normalized task: {normalized_task}")

    if not normalized_ad_import_tasks:
        logger.info("No valid AD import tasks to process after validation and normalization. Exiting.")
        sys.exit(0) # Successful exit, as there's nothing to do.

    # Execute the main workflow
    exit_code = 0
    try:
        # Ensure all required arguments for run_ad_import_workflow are correctly passed
        # and are not None if they are non-optional.
        # ad_provider_id, ad_provider_name_for_logging, ad_search_username_val, ad_search_password_val
        # have been validated or have fatal exits if issues arise.
        
        workflow_success = run_ad_import_workflow(
            ome_client_instance,      # type: ignore # Already checked for None
            ad_provider_id,           # type: ignore # Already checked for None and type
            ad_provider_name_for_logging, # type: ignore
            ad_search_username_val,   # type: ignore
            ad_search_password_val,   # type: ignore
            normalized_ad_import_tasks,
            logger # Pass the main module logger
        )
        if not workflow_success:
            logger.warning("AD import workflow completed with one or more task-level errors or critical issues.")
            # Decide if this constitutes a non-zero exit code.
            # If any task fails but the script itself runs, it might still be 0.
            # For now, let's assume workflow_success reflects if the script could run,
            # not necessarily if all tasks were 100% successful without warnings.
            # If critical errors occurred in run_ad_import_workflow, overall_success would be false.
    except Exception as e:
        logger.fatal(f"Core AD import workflow failed unexpectedly: {e}", exc_info=True)
        exit_code = 1 # Indicate a critical script failure
    finally:
        if ome_client_instance:
            try:
                ome_client_instance.logout()
                logger.info("Successfully logged out from OME.")
            except Exception as e:
                logger.warning(f"Error during OME logout: {e}", exc_info=args.debug)
                
    logger.info(f"OME AD Group Import script finished with exit code {exit_code}.")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
