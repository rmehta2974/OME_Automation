#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main entry point for the OME Static Group Management script.
Handles argument parsing, orchestrates the workflow, and manages overall script execution.
"""

# __version__ = "1.3.2" # Previous Version
__version__ = "1.3.3" # Corrected len() call for action='append' CLI arguments.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ...
# 2025-05-14 | 1.3.2   | Gemini     | Modified process_group_task to correctly look up and pass the integer ID of the parent group.
# 2025-05-14 | 1.3.3   | Gemini     | Corrected calculation of total_cli_groups to handle None when action='append' CLI arg is not provided.

import argparse
import sys
import logging
import json
import requests.exceptions
from typing import Dict, List, Optional, Tuple, Any

import utils # Ensure this is utils v1.0.4 or later
import constants # Ensure this is constants_v1_2_0_equiv (internally v1.2.3) or later
import input_validator
import ome_client # Ensure this is ome_client v1.10.14 or later
import concurrent.futures

logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Manage static device groups in OpenManage Enterprise (OME).")
    parser.add_argument('--ome-url', help='OpenManage Enterprise URL', metavar='URL')
    parser.add_argument('--username', help='OME Username', metavar='USERNAME')
    parser.add_argument('--password', help='OME Password', metavar='PASSWORD')
    parser.add_argument('--config', help='Path to a JSON configuration file', metavar='FILE_PATH')
    parser.add_argument(
        f'--{constants.STATIC_GROUP_CLI_ARG_NAME}', # This uses action='append'
        action='append',
        help='JSON string defining a single static group. Can be specified multiple times.',
        metavar='JSON_STRING'
    )
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--log-file', help='Path to a file to write logs to', metavar='LOG_FILE_PATH')
    args = parser.parse_args()

    utils.setup_logger(debug=args.debug, log_file_path=args.log_file)
    logger.info(f"Static Group Management Script started (Version: {__version__}).")
    logger.debug(f"Parsed arguments: {args}")

    config: Optional[Dict] = None
    if args.config:
        logger.info(f"Attempting to load configuration from '{args.config}'...")
        config = utils.load_config(args.config, logger)
        if config is None:
            logger.fatal(f"Failed to load or parse configuration file '{args.config}'. Exiting.")
            sys.exit(1)
        logger.info("Configuration file loaded successfully.")

    logger.info("Collecting and validating OME credentials...")
    ome_creds, is_ome_creds_valid = utils.collect_and_validate_credentials(
        args, config, constants.OME_AUTH_REQUIRED_KEYS,
        constants.OME_CRED_CONFIG_SECTION, constants.OME_CLI_CRED_MAP,
        input_validator.validate_ome_credentials_specific, logger
    )
    if not is_ome_creds_valid:
        logger.fatal("Invalid OME credentials. Exiting.")
        sys.exit(1)
    logger.info("OME credentials validated.")

    logger.info("Collecting static group definitions...")
    valid_raw_groups, invalid_group_details = utils.collect_and_validate_list_inputs(
        args, config, constants.STATIC_GROUP_CLI_ARG_NAME,
        constants.STATIC_GROUP_CONFIG_SECTION,
        input_validator.validate_static_group_definition_specific, logger
    )
    
    # --- CORRECTED Strict Exit Logic ---
    # getattr will return None if --StaticGroup was not provided, because action='append' sets it to None by default.
    cli_groups_value = getattr(args, constants.STATIC_GROUP_CLI_ARG_NAME, None)
    total_cli_groups = len(cli_groups_value) if cli_groups_value is not None else 0
    
    config_groups_list = utils.get_config_section(config, constants.STATIC_GROUP_CONFIG_SECTION, [])
    total_config_groups = len(config_groups_list) if isinstance(config_groups_list, list) else 0
    total_input_group_items = total_cli_groups + total_config_groups

    if total_input_group_items == 1 and not valid_raw_groups:
        logger.fatal("Only one static group definition provided, and it is invalid. Exiting.")
        sys.exit(1)
    if invalid_group_details:
        logger.warning(f"Skipping {len(invalid_group_details)} invalid static group definition(s):")
        for item, errors, src_info in invalid_group_details:
            logger.error(f"  Invalid item from {src_info}: {item} -> Errors: {errors}")

    normalized_tasks: List[Dict] = []
    logger.debug(f"Normalizing {len(valid_raw_groups)} valid raw group definitions...")
    for raw_group_dict in valid_raw_groups:
        group_task = {
            "group_name": raw_group_dict['group_name'],
            "create": raw_group_dict.get('create', constants.DEFAULT_CREATE_FLAG),
            "parent_group_name": raw_group_dict.get('parent_group', constants.DEFAULT_PARENT_GROUP),
            "devices_raw": [], "identifier_type": None, "devices_resolved_ids": []
        }
        if 'devices' in raw_group_dict:
            group_task['identifier_type'] = raw_group_dict.get('identifier_type')
            group_task['devices_raw'] = utils.parse_devices_input(raw_group_dict['devices'], logger)
        else:
            logger.debug(f"No 'devices' key found for group '{group_task.get('group_name', 'Unknown Group')}' during normalization.")
        normalized_tasks.append(group_task)
    logger.info(f"Prepared {len(normalized_tasks)} static group task(s).")
    if not normalized_tasks:
        logger.info("No valid static group tasks to process. Exiting.")
        sys.exit(0)

    logger.info(f"Connecting to OME at {ome_creds.get('url')}...")
    try:
        ome_client_instance = ome_client.OmeClient(ome_creds['url'], ome_creds['username'], ome_creds['password'])
        ome_client_instance.authenticate()
        logger.info("Authentication with OME successful.")
    except Exception as e:
        logger.fatal(f"Failed OME client setup/authentication: {e}", exc_info=args.debug)
        sys.exit(1)

    logger.info("Starting processing of static group tasks...")
    for group_task in normalized_tasks:
        process_group_task(ome_client_instance, group_task, logger)

    logger.info("All static group tasks processed.")
    logger.info("Script finished.")
    sys.exit(0)

def process_group_task(ome_client_instance: ome_client.OmeClient,
                       group_task: dict,
                       logger: logging.Logger):
    group_name = group_task.get('group_name', 'Unknown Group')
    logger.info(f"--- Processing group '{group_name}' ---")
    logger.debug(f"Task details: {group_task}")
    group_id_to_update: Optional[str] = None
    group_existed_beforehand: bool = False
    
    parent_id_for_creation: Optional[int] = None
    parent_group_name_to_find = group_task.get('parent_group_name', constants.DEFAULT_PARENT_GROUP)

    if parent_group_name_to_find:
        logger.debug(f"Resolving Parent ID for parent group name: '{parent_group_name_to_find}'")
        parent_group_obj = ome_client_instance.get_group_by_name(parent_group_name_to_find)
        if parent_group_obj and parent_group_obj.get('Id') is not None:
            try:
                parent_id_for_creation = int(parent_group_obj['Id'])
                logger.info(f"Found parent group '{parent_group_name_to_find}' with ID: {parent_id_for_creation}.")
            except (ValueError, TypeError):
                logger.error(f"ID '{parent_group_obj['Id']}' for parent group '{parent_group_name_to_find}' is not a valid integer. Cannot create child group '{group_name}'.")
                return
        else:
            logger.error(f"Specified parent group '{parent_group_name_to_find}' not found or has no ID. Cannot create child group '{group_name}'.")
            return
    else:
        logger.warning(f"No parent group name specified for '{group_name}'. OME default placement will occur.")
        parent_id_for_creation = None # Let ome_client.create_static_group handle this (it expects int or None)

    try:
        logger.debug(f"Checking if group '{group_name}' exists...")
        existing_group = ome_client_instance.get_group_by_name(group_name)
        group_existed_beforehand = (existing_group is not None)
        if existing_group:
            group_id_raw = existing_group.get('Id')
            if group_id_raw is not None: group_id_to_update = str(group_id_raw); logger.info(f"Group '{group_name}' exists (ID: {group_id_to_update}).")
            else: logger.error(f"Group '{group_name}' found but missing ID. Skipping."); return
        else:
            logger.info(f"Group '{group_name}' not found.")
            if group_task.get('create', False):
                logger.info(f"Creating group '{group_name}' under parent ID: {parent_id_for_creation} (derived from '{parent_group_name_to_find}').")
                try:
                    new_group_id_str = ome_client_instance.create_static_group(group_name, parent_id_for_creation)
                    if new_group_id_str: group_id_to_update = new_group_id_str
                    else: logger.error(f"Group creation '{group_name}' failed to return ID. Skipping."); return
                except Exception as e: logger.error(f"Failed to create group '{group_name}': {e}. Skipping."); return
            else: logger.warning(f"Group '{group_name}' not found and create=false. Skipping."); return
        if group_id_to_update is None: logger.error(f"Internal error: group_id_to_update is None for '{group_name}'. Skipping."); return

        resolved_device_ids: List[str] = []
        if group_task.get('devices_raw'):
             identifier_type = group_task.get('identifier_type')
             raw_devices_list = group_task['devices_raw']
             if identifier_type and raw_devices_list:
                 logger.info(f"Resolving {len(raw_devices_list)} devices ({identifier_type}) for group '{group_name}' (ID: {group_id_to_update}).")
                 resolved_device_ids = resolve_device_identifiers(
                     ome_client_instance, identifier_type, raw_devices_list, logger,
                     target_group_id=group_id_to_update, target_group_name=group_name,
                     group_existed_beforehand=group_existed_beforehand
                 )
                 unresolved_count = len(raw_devices_list) - len(resolved_device_ids)
                 if resolved_device_ids: logger.info(f"Resolved {len(resolved_device_ids)} device(s) needing addition.")
                 if unresolved_count > 0: logger.warning(f"{unresolved_count} device(s) unresolved or already in group '{group_name}'.")
             else: logger.debug(f"Skipping resolution for '{group_name}' due to missing type or empty device list.")
        else: logger.debug(f"No 'devices_raw' for group '{group_name}'.")

        if resolved_device_ids:
            logger.info(f"Adding {len(resolved_device_ids)} resolved device(s) to group '{group_name}' (ID: {group_id_to_update}).")
            try: ome_client_instance.add_devices_to_group(group_id_to_update, resolved_device_ids)
            except Exception as e: logger.error(f"Failed to add devices to group '{group_name}': {e}")
        else: logger.debug(f"No newly resolved devices to add to group '{group_name}'.")
    except Exception as e: logger.error(f"Unexpected error processing group '{group_name}': {e}", exc_info=True)
    logger.info(f"--- Finished processing group '{group_name}' ---")

def resolve_device_identifiers(ome_client_instance: ome_client.OmeClient,
                               identifier_type: str,
                               raw_device_values: list,
                               logger: logging.Logger,
                               target_group_id: Optional[str],
                               target_group_name: Optional[str],
                               group_existed_beforehand: bool
                               ) -> list:
    resolved_ids: List[str] = []
    if not raw_device_values: return resolved_ids
    logger.debug(f"Starting device resolution for {len(raw_device_values)} items ({identifier_type}) for target group '{target_group_name}'. Pre-check if group existed: {group_existed_beforehand}")
    max_workers = 20
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_value = {
            executor.submit(ome_client_instance.find_device_id,
                            identifier_type, value,
                            target_group_id=target_group_id, target_group_name=target_group_name,
                            check_target_group_membership=group_existed_beforehand): value
            for value in raw_device_values
        }
        for future in concurrent.futures.as_completed(future_to_value):
            raw_value = future_to_value[future]
            try:
                device_id = future.result()
                if device_id is not None: resolved_ids.append(device_id)
            except Exception as exc: logger.error(f"Error resolving device '{raw_value}' ({identifier_type}): {exc}", exc_info=True)
    return resolved_ids

if __name__ == "__main__":
    main()
