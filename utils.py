#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reusable utility functions for the OME automation scripts.
Includes logging setup, config loading, general input handling patterns,
and parsing helpers.
"""

# __version__ = "1.0.0" # Previous Version
__version__ = "1.0.1" # Enhanced read_file_list for CSV handling

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# 2025-04-30 | 1.0.0   | Rahul Mehta| Initial file creation.
# 2025-05-13 | 1.0.1   | Rahul Mehta     | Modified read_file_list to handle comma-separated values within lines of a file.

import logging
import json
import os
import sys
from typing import Dict, List, Optional, Tuple, Any, Callable

# Get logger for this module
logger = logging.getLogger(__name__)


def setup_logger(debug: bool = False, log_file_path: Optional[str] = None, log_level=logging.INFO):
    """
    Configures the root logger for the script.

    Args:
        debug: If True, sets level to DEBUG and uses a more verbose format.
        log_file_path: Optional path to a file to write logs to.
        log_level: The minimum logging level if not in debug mode.
    """
    if logging.root.hasHandlers():
        logging.root.handlers.clear()

    level = logging.DEBUG if debug else log_level
    formatter_str = '%(asctime)s - %(levelname)s - %(name)s - %(funcName)s - %(message)s' if debug \
                    else '%(asctime)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(formatter_str)

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(console_handler)

    # File Handler (Optional)
    if log_file_path:
        try:
            file_handler = logging.FileHandler(log_file_path, mode='a') # Append mode
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            root_logger.info(f"Logging to file: {log_file_path}")
        except Exception as e:
            root_logger.error(f"Failed to set up log file at '{log_file_path}': {e}")


def load_config(file_path: str, logger_instance: logging.Logger) -> Optional[Dict]:
    """
    Loads and parses a JSON configuration file.
    """
    if not os.path.exists(file_path):
        logger_instance.error(f"Configuration file not found at '{file_path}'.")
        return None
    if not os.path.isfile(file_path):
         logger_instance.error(f"Configuration path '{file_path}' is not a file.")
         return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        if not isinstance(config_data, dict):
             logger_instance.error(f"Config file '{file_path}' must contain a JSON object at root.")
             return None
        logger_instance.debug(f"Successfully loaded config file '{file_path}'.")
        return config_data
    except json.JSONDecodeError as e:
        logger_instance.error(f"Failed to parse JSON config file '{file_path}': {e}")
        return None
    except Exception as e:
        logger_instance.error(f"Unexpected error loading config '{file_path}': {e}")
        return None


def get_config_section(config_data: Optional[Dict], section_name: str, default_value: Any = None) -> Any:
    """
    Safely retrieves a specific section (key) from the configuration dictionary.
    """
    if config_data is None:
        logger.debug(f"Config data is None, returning default for section '{section_name}'.")
        return default_value
    section_data = config_data.get(section_name, default_value)
    if section_data is default_value and section_name in config_data:
        logger.debug(f"Config section '{section_name}' found with default-like value.")
    elif section_data is default_value:
         logger.debug(f"Config section '{section_name}' not found, returning default.")
    else:
         logger.debug(f"Successfully retrieved config section '{section_name}'.")
    return section_data


def parse_devices_input(devices_input: Any) -> List[str]:
    """
    Parses the raw 'devices' input value (string or list) into a list of strings.
    Handles "file:" prefix for loading from a file.
    """
    identifiers: List[str] = []
    if isinstance(devices_input, str):
        if devices_input.lower().startswith("file:"):
            file_path = devices_input[len("file:"):]
            logger.debug(f"Parsing devices from file: {file_path}")
            # read_file_list now handles comma separation within lines
            identifiers = read_file_list(file_path, logger)
        else:
            logger.debug(f"Parsing devices from string: '{devices_input}'")
            # Split by comma, then strip whitespace from each item
            # This also handles spaces around commas.
            identifiers = [item.strip() for item in devices_input.split(',') if item.strip()]
    elif isinstance(devices_input, list):
        logger.debug(f"Parsing devices from list input ({len(devices_input)} items).")
        # Ensure all elements are strings and strip whitespace, also handle potential inner commas if list contains strings with commas
        temp_identifiers: List[str] = []
        for item_in_list in devices_input:
            if isinstance(item_in_list, (str, int, float)):
                # If item in list is a string, it might contain commas
                if isinstance(item_in_list, str):
                    temp_identifiers.extend([sub_item.strip() for sub_item in item_in_list.split(',') if sub_item.strip()])
                else: # For int/float, convert to string and add
                    temp_identifiers.append(str(item_in_list).strip())
            elif item_in_list is not None: # Log if item is not processable but not None
                 logger.warning(f"Skipping non-string/numeric item in 'devices' list: {item_in_list} (type: {type(item_in_list)})")
        identifiers = [id_str for id_str in temp_identifiers if id_str] # Filter out any empty strings resulting from split

        if len(identifiers) < len(devices_input) and not all(isinstance(i, str) and ',' in i for i in devices_input):
             # This warning might be noisy if the input list was intentionally like ["ip1,ip2", "ip3"]
             # Consider refining this warning based on expected list structure.
             logger.debug(f"Processed {len(identifiers)} identifiers from input list of {len(devices_input)} items (some items might have been comma-separated strings).")
    else:
        logger.warning(f"Invalid data type for 'devices' input: {type(devices_input)}. Expected string or list.")
    return identifiers


def read_file_list(file_path: str, logger_instance: logging.Logger) -> List[str]:
    """
    Reads a list of items from a file.
    Each line in the file can contain one or more identifiers separated by commas.
    All identifiers are stripped of whitespace and empty ones are skipped.
    """
    all_items: List[str] = []
    logger_instance.debug(f"Attempting to read device list from file: '{file_path}'")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_number, line_content in enumerate(f, 1):
                stripped_line = line_content.strip()
                if not stripped_line or stripped_line.startswith('#'): # Skip empty lines and comments
                    continue
                # Split the line by comma, then strip each part
                line_items = [item.strip() for item in stripped_line.split(',') if item.strip()]
                if line_items:
                    all_items.extend(line_items)
                else:
                    logger_instance.debug(f"Line {line_number} in '{file_path}' is empty after stripping/splitting.")
        logger_instance.info(f"Read {len(all_items)} identifiers from file '{file_path}'.")
    except FileNotFoundError:
        logger_instance.error(f"Device list file not found at '{file_path}'.")
    except Exception as e:
        logger_instance.error(f"An error occurred while reading device list file '{file_path}': {e}")
    return all_items

# --- Reusable Input Collection and Validation Patterns ---
# (collect_and_validate_credentials and collect_and_validate_list_inputs remain unchanged from v1.0.0)
def collect_and_validate_credentials(
    args: argparse.Namespace,
    config_data: Optional[Dict],
    required_keys: set,
    config_section_name: str,
    cli_arg_map: Dict[str, str],
    specific_validator_func: Callable[[Dict, str], Tuple[bool, List[str]]],
    logger_instance: logging.Logger
) -> Tuple[Dict, bool]:
    """
    Collects credential-like data from CLI and config, validates it.
    """
    creds_dict: Dict[str, Any] = {}
    logger_instance.debug(f"Collecting credentials/config for '{config_section_name}'...")

    # 1. Collect from CLI arguments (highest priority)
    for cli_arg_name, dict_key_name in cli_arg_map.items():
        cli_value = getattr(args, cli_arg_name, None)
        if cli_value is not None:
            creds_dict[dict_key_name] = cli_value
            logger_instance.debug(f"Collected '{dict_key_name}' from CLI arg '--{cli_arg_name.replace('_', '-')}' = '{cli_value}'.")

    # 2. Get section from config file (if loaded)
    config_section = get_config_section(config_data, config_section_name, {}) # Default to empty dict
    if config_section: logger_instance.debug(f"Found config section '{config_section_name}'.")
    else: logger_instance.debug(f"Config section '{config_section_name}' not found or config not loaded.")

    # 3. Fill missing keys from config section (respecting CLI priority)
    all_potential_keys = required_keys.union(set(cli_arg_map.values()))
    for key in all_potential_keys:
         if key not in creds_dict and key in config_section: # Not set by CLI, but present in config
             creds_dict[key] = config_section[key]
             logger_instance.debug(f"Collected '{key}' from config section '{config_section_name}'.")

    # 4. Perform specific validation
    is_valid, errors = specific_validator_func(creds_dict, f"Source: CLI and/or config section '{config_section_name}'")
    if not is_valid:
        logger_instance.error(f"Validation failed for '{config_section_name}':")
        for error in errors: logger_instance.error(f"  - {error}")
    return creds_dict, is_valid


def collect_and_validate_list_inputs(
    args: argparse.Namespace,
    config_data: Optional[Dict],
    cli_arg_name: str,
    config_section_name: str,
    item_validator_func: Callable[[Dict, str], Tuple[bool, List[str]]],
    logger_instance: logging.Logger
) -> Tuple[List[Dict], List[Tuple[Any, List[str], str]]]:
    """
    Collects a list of dict items from CLI and config, validates each.
    """
    raw_items_with_source: List[Tuple[Dict, str]] = []
    parsing_errors_info: List[Tuple[Any, List[str], str]] = []
    logger_instance.debug(f"Collecting list items from CLI '--{cli_arg_name}' and config '{config_section_name}'...")

    # 1. Collect from CLI arguments (expecting list of JSON strings)
    cli_arg_values = getattr(args, cli_arg_name, []) or [] # Ensure it's a list
    if cli_arg_values:
        logger_instance.debug(f"Found {len(cli_arg_values)} item(s) from CLI arg '--{cli_arg_name}'.")
        for i, json_string in enumerate(cli_arg_values):
            try:
                parsed_item = json.loads(json_string)
                if isinstance(parsed_item, dict):
                    raw_items_with_source.append((parsed_item, f"CLI arg --{cli_arg_name} index {i}"))
                else:
                    parsing_errors_info.append((json_string, ["Input is not a JSON object."], f"CLI --{cli_arg_name} index {i}"))
            except json.JSONDecodeError as e:
                parsing_errors_info.append((json_string, [f"JSON parsing failed: {e}"], f"CLI --{cli_arg_name} index {i}"))
            except Exception as e:
                 parsing_errors_info.append((json_string, [f"Unexpected error: {e}"], f"CLI --{cli_arg_name} index {i}"))

    # 2. Collect from config file section (expecting a list of dictionaries)
    config_section_data = get_config_section(config_data, config_section_name, [])
    if isinstance(config_section_data, list):
        if config_section_data: logger_instance.debug(f"Found {len(config_section_data)} item(s) in config '{config_section_name}'.")
        for i, item_data in enumerate(config_section_data):
            if isinstance(item_data, dict):
                raw_items_with_source.append((item_data, f"config '{config_section_name}', index {i}"))
            else:
                parsing_errors_info.append((item_data, ["Item in config list is not a dictionary."], f"config '{config_section_name}', index {i}"))
    elif config_section_data is not None: # Section exists but is not a list
         logger_instance.warning(f"Config section '{config_section_name}' is not a list. Skipping.")

    # 3. Validate each collected item and segregate
    valid_items: List[Dict] = []
    invalid_item_details: List[Tuple[Any, List[str], str]] = list(parsing_errors_info) # Start with parsing errors

    if raw_items_with_source:
        logger_instance.debug(f"Validating {len(raw_items_with_source)} collected items...")
        for item_dict, source_info in raw_items_with_source:
            is_item_valid, item_errors = item_validator_func(item_dict, source_info)
            if is_item_valid:
                valid_items.append(item_dict)
                logger_instance.debug(f"Item from {source_info} validated successfully.")
            else:
                invalid_item_details.append((item_dict, item_errors, source_info))
                logger_instance.debug(f"Item from {source_info} validation failed.")
    return valid_items, invalid_item_details
