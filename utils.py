#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reusable utility functions for the OME automation scripts.
Includes logging setup, config loading, general input handling patterns,
and parsing helpers.
"""

# __version__ = "1.0.4" # Previous Version from user upload
__version__ = "1.0.5" # Added get_single_input function for ome_config_manager.py

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history from 1.0.4)
# 2025-05-15 | 1.0.5   | Rahul Mehta    | Added get_single_input function to fetch single configuration items
#            |         |            | from CLI (as JSON string or direct value) or config file section.

import logging
import json
import os
import sys
import argparse # For type hinting argparse.Namespace
from typing import Dict, List, Optional, Tuple, Any, Callable

# Get logger for this module. It will use the configuration set up by the main script.
# If this module is used standalone without prior logging setup, basic logging might occur.
module_logger = logging.getLogger(__name__)


def setup_logger(debug: bool = False,
                 log_file_path: Optional[str] = None,
                 log_level: int = logging.INFO,
                 logger_to_configure: Optional[logging.Logger] = None): # Added logger_to_configure
    """
    Configures a specific logger or the root logger.
    If logger_to_configure is None, configures the root logger.
    """
    target_logger = logger_to_configure if logger_to_configure else logging.getLogger()

    # Clear existing handlers from the target logger to avoid duplicate logs
    if target_logger.hasHandlers():
        # print(f"Clearing existing handlers for logger: {target_logger.name}") # Debug print
        for handler in target_logger.handlers[:]: # Iterate over a copy
            target_logger.removeHandler(handler)
            handler.close() # Close handler to release resources like file locks

    level = logging.DEBUG if debug else log_level
    formatter_str = '%(asctime)s - %(levelname)s - %(name)s - %(funcName)s - %(message)s' if debug \
                    else '%(asctime)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(formatter_str)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    target_logger.setLevel(level) # Set overall minimum level for this logger
    target_logger.addHandler(console_handler)
    # Prevent log propagation if we are configuring a specific logger and not the root
    # to avoid messages appearing twice if root also has handlers.
    if logger_to_configure is not None and logger_to_configure.name != logging.root.name:
        target_logger.propagate = False


    if log_file_path:
        try:
            # Ensure directory exists for log file
            log_dir = os.path.dirname(log_file_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                target_logger.info(f"Created directory for log file: {log_dir}")

            file_handler = logging.FileHandler(log_file_path, mode='a', encoding='utf-8')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(level)
            target_logger.addHandler(file_handler)
            target_logger.info(f"Logging to file: {log_file_path}")
        except Exception as e:
            target_logger.error(f"Failed to set up log file at '{log_file_path}': {e}")
    
    # if target_logger.name == logging.root.name:
    #     module_logger.debug("Root logger configured.")
    # else:
    #     module_logger.debug(f"Specific logger '{target_logger.name}' configured.")


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
    # Use module_logger for utility function's own logging if no specific logger is passed
    # However, for consistency, it's better if the calling script's logger is used.
    # This function is simple enough that its own logging might not be critical.
    # For now, assume the calling context's logger will report issues if default_value is returned unexpectedly.

    if config_data is None:
        # module_logger.debug(f"Config data is None, returning default for section '{section_name}'.")
        return default_value
    
    section_data = config_data.get(section_name) # Get value, will be None if key doesn't exist
    
    if section_data is None and section_name not in config_data: # Key truly missing
        # module_logger.debug(f"Config section '{section_name}' not found, returning default value.")
        return default_value
    # module_logger.debug(f"Retrieved config section '{section_name}'.")
    return section_data # Returns None if key exists but value is null, or actual value


def get_single_input(
    cli_arg_value: Optional[Any],
    config_data: Optional[Dict],
    config_section_name: str,
    logger_instance: logging.Logger,
    is_json_string_cli: bool = False
) -> Optional[Any]:
    """
    Retrieves a single configuration item.
    Priority:
    1. CLI argument value (parsed as JSON if is_json_string_cli is True).
    2. Value from the specified section in the config_data dictionary.

    Args:
        cli_arg_value (Optional[Any]): Value from the command-line argument.
        config_data (Optional[Dict]): Loaded configuration dictionary (from config.json).
        config_section_name (str): The key/section name to look for in config_data.
        logger_instance (logging.Logger): Logger for logging messages.
        is_json_string_cli (bool): If True and cli_arg_value is a string, attempt to parse as JSON.

    Returns:
        Optional[Any]: The retrieved configuration item (can be dict, list, str, etc.), or None.
    """
    logger_instance.debug(f"Attempting to get single input. CLI value: '{cli_arg_value}', Config section: '{config_section_name}'.")

    if cli_arg_value is not None:
        logger_instance.debug(f"Using value from CLI argument for '{config_section_name}'.")
        if is_json_string_cli and isinstance(cli_arg_value, str):
            try:
                parsed_cli_value = json.loads(cli_arg_value)
                logger_instance.debug(f"Successfully parsed CLI JSON string for '{config_section_name}'.")
                return parsed_cli_value
            except json.JSONDecodeError as e:
                logger_instance.error(f"Failed to parse CLI argument value as JSON for '{config_section_name}': '{cli_arg_value}'. Error: {e}. Returning as raw string if non-empty, else None.")
                # Fallback: return as string if it's non-empty, or None if it was just bad JSON.
                # Or, you might want to make this a hard failure.
                return cli_arg_value if cli_arg_value.strip() else None
            except Exception as e: # Catch any other unexpected error during parsing
                logger_instance.error(f"Unexpected error parsing CLI JSON string for '{config_section_name}': {e}. Value: '{cli_arg_value}'. Returning as raw string if non-empty, else None.")
                return cli_arg_value if isinstance(cli_arg_value, str) and cli_arg_value.strip() else None
        else:
            # CLI value is provided but not expected to be a JSON string, or it's not a string
            return cli_arg_value
    
    # If CLI argument was not provided, try config file
    if config_data:
        config_value = get_config_section(config_data, config_section_name) # Default is None
        if config_value is not None:
            logger_instance.debug(f"Using value from config file section '{config_section_name}'.")
            return config_value
        else:
            logger_instance.debug(f"Config section '{config_section_name}' not found or is null in config file.")
            return None # Explicitly return None if section not found or value is null
            
    logger_instance.debug(f"No value found from CLI or config file for '{config_section_name}'.")
    return None


def parse_devices_input(devices_input: Any, logger_instance: logging.Logger) -> List[str]:
    """
    Parses the raw 'devices' input value into a flat list of unique string identifiers.
    Handles:
    - Direct string: "id1,id2,id3"
    - Single string identifier: "dns.name.com"
    - List: ["id1", "file:path/to/devices.txt", "id2,id3", "dns.name.com"]
    - "file:" prefix in strings to load identifiers from a file.
    """
    collected_identifiers: List[str] = []

    if isinstance(devices_input, str):
        stripped_input = devices_input.strip()
        if not stripped_input: pass
        elif stripped_input.lower().startswith("file:"):
            file_path = stripped_input[len("file:"):]
            logger_instance.debug(f"Input string is a file path: '{file_path}'. Reading file.")
            collected_identifiers.extend(read_file_list(file_path, logger_instance))
        else:
            logger_instance.debug(f"Input string is direct CSV or single ID: '{stripped_input}'. Splitting by comma.")
            collected_identifiers.extend([item.strip() for item in stripped_input.split(',') if item.strip()])
    elif isinstance(devices_input, list):
        logger_instance.debug(f"Input is a list. Processing {len(devices_input)} items recursively.")
        for item_in_list in devices_input:
            collected_identifiers.extend(parse_devices_input(item_in_list, logger_instance))
    elif isinstance(devices_input, (int, float)):
        logger_instance.debug(f"Input is a number: {devices_input}. Converting to string.")
        num_str = str(devices_input).strip()
        if num_str: collected_identifiers.append(num_str)
    elif devices_input is not None:
        logger_instance.warning(f"Invalid data type for 'devices' input item: {type(devices_input)} ('{devices_input}'). Expected string, list, int, or float.")

    seen = set()
    unique_identifiers = [x for x in collected_identifiers if not (x in seen or seen.add(x))]
    
    if len(collected_identifiers) != len(unique_identifiers):
        logger_instance.debug(f"Removed {len(collected_identifiers) - len(unique_identifiers)} duplicate identifiers. Final count: {len(unique_identifiers)}")
    return unique_identifiers


def read_file_list(file_path: str, logger_instance: logging.Logger) -> List[str]:
    """
    Reads a list of items from a file.
    Each line can contain one or more identifiers separated by commas.
    """
    all_items: List[str] = []
    logger_instance.debug(f"Attempting to read device list from file: '{file_path}'")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_number, line_content in enumerate(f, 1):
                stripped_line = line_content.strip()
                if not stripped_line or stripped_line.startswith('#'): continue
                line_items = [item.strip() for item in stripped_line.split(',') if item.strip()]
                if line_items: all_items.extend(line_items)
                else: logger_instance.debug(f"Line {line_number} in '{file_path}' is empty after processing.")
        logger_instance.info(f"Read {len(all_items)} identifiers from file '{file_path}'.")
    except FileNotFoundError:
        logger_instance.error(f"Device list file not found at '{file_path}'.")
    except Exception as e:
        logger_instance.error(f"An error occurred while reading device list file '{file_path}': {e}")
    return all_items

# --- Reusable Input Collection and Validation Patterns ---
def collect_and_validate_credentials(
    args: argparse.Namespace,
    config_data: Optional[Dict],
    required_keys: set,
    config_section_name: str,
    cli_arg_map: Dict[str, str],
    specific_validator_func: Callable[[Dict, str], Tuple[bool, List[str]]],
    logger_instance: logging.Logger
) -> Tuple[Dict, bool]:
    creds_dict: Dict[str, Any] = {}
    logger_instance.debug(f"Collecting credentials/config for '{config_section_name}'...")
    for cli_arg_name, dict_key_name in cli_arg_map.items():
        cli_value = getattr(args, cli_arg_name, None)
        if cli_value is not None:
            creds_dict[dict_key_name] = cli_value
            logger_instance.debug(f"Collected '{dict_key_name}' from CLI arg '--{cli_arg_name.replace('_', '-')}'") # Removed value for security
    
    config_section = get_config_section(config_data, config_section_name, {}) # Default to empty dict
    if not isinstance(config_section, dict): # Ensure it's a dict if found but wrong type
        logger_instance.warning(f"Config section '{config_section_name}' is not a dictionary. Found type: {type(config_section)}. Treating as empty.")
        config_section = {}

    all_potential_keys = required_keys.union(set(cli_arg_map.values()))
    for key in all_potential_keys:
         if key not in creds_dict and key in config_section: # Prioritize CLI if already set
             creds_dict[key] = config_section[key]
             logger_instance.debug(f"Collected '{key}' from config section '{config_section_name}'.")
    
    is_valid, errors = specific_validator_func(creds_dict, f"Source: CLI and/or config section '{config_section_name}'")
    if not is_valid:
        logger_instance.error(f"Validation failed for '{config_section_name}':")
        for error in errors: logger_instance.error(f"  - {error}")
    return creds_dict, is_valid

def collect_and_validate_list_inputs(
    args: argparse.Namespace,
    config_data: Optional[Dict],
    cli_arg_name: str, # The dest name in argparse for the appendable CLI arg
    config_section_name: str,
    item_validator_func: Callable[[Dict, str], Tuple[bool, List[str]]],
    logger_instance: logging.Logger
) -> Tuple[List[Dict], List[Tuple[Any, List[str], str]]]:
    raw_items_with_source: List[Tuple[Dict, str]] = []
    parsing_errors_info: List[Tuple[Any, List[str], str]] = []
    logger_instance.debug(f"Collecting list items from CLI '--{cli_arg_name.replace('_','-')}' and config '{config_section_name}'...")
    
    # getattr(args, cli_arg_name, []) might return None if action='append' and arg not used. Default to []
    cli_arg_values = getattr(args, cli_arg_name, None) or [] 
    
    if cli_arg_values: # Ensure it's not None and is iterable
        logger_instance.debug(f"Found {len(cli_arg_values)} item(s) from CLI arg for '{cli_arg_name}'.")
        for i, json_string_item in enumerate(cli_arg_values):
            if isinstance(json_string_item, str):
                try:
                    parsed_item = json.loads(json_string_item)
                    if isinstance(parsed_item, dict):
                        raw_items_with_source.append((parsed_item, f"CLI arg for '{cli_arg_name}', index {i}"))
                    else:
                        parsing_errors_info.append((json_string_item, ["Input is not a JSON object."], f"CLI for '{cli_arg_name}', index {i}"))
                except json.JSONDecodeError as e:
                    parsing_errors_info.append((json_string_item, [f"JSON parsing failed: {e}"], f"CLI for '{cli_arg_name}', index {i}"))
                except Exception as e:
                     parsing_errors_info.append((json_string_item, [f"Unexpected error parsing CLI item: {e}"], f"CLI for '{cli_arg_name}', index {i}"))
            else: # Should not happen if metavar='JSON_STRING' is used and user provides strings.
                 parsing_errors_info.append((json_string_item, ["CLI item is not a string to be parsed as JSON."], f"CLI for '{cli_arg_name}', index {i}"))

    config_section_data = get_config_section(config_data, config_section_name, []) # Default to empty list
    if isinstance(config_section_data, list):
        if config_section_data: logger_instance.debug(f"Found {len(config_section_data)} item(s) in config section '{config_section_name}'.")
        for i, item_data in enumerate(config_section_data):
            if isinstance(item_data, dict):
                raw_items_with_source.append((item_data, f"config section '{config_section_name}', index {i}"))
            else:
                parsing_errors_info.append((item_data, ["Item in config list is not a dictionary."], f"config section '{config_section_name}', index {i}"))
    elif config_section_data is not None: # If section exists but is not a list
         logger_instance.warning(f"Config section '{config_section_name}' is not a list (type: {type(config_section_data)}). Skipping items from this config section.")
    
    valid_items: List[Dict] = []
    # Initialize with parsing errors, then add validation errors
    invalid_item_details: List[Tuple[Any, List[str], str]] = list(parsing_errors_info) 
    
    if raw_items_with_source:
        logger_instance.debug(f"Validating {len(raw_items_with_source)} collected raw items for '{config_section_name}' tasks...")
        for item_dict, source_info in raw_items_with_source:
            is_item_valid, item_errors = item_validator_func(item_dict, source_info)
            if is_item_valid:
                valid_items.append(item_dict)
            else:
                invalid_item_details.append((item_dict, item_errors, source_info))
    elif not parsing_errors_info: # No raw items and no parsing errors means no input was found
        logger_instance.debug(f"No items found from CLI or config for '{config_section_name}' tasks.")


    return valid_items, invalid_item_details
