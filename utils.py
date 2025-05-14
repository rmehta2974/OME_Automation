#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reusable utility functions for the OME automation scripts.
Includes logging setup, config loading, general input handling patterns,
and parsing helpers.
"""

# __version__ = "1.0.3" # Previous Version
__version__ = "1.0.4" # Corrected recursion in parse_devices_input

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# 2025-05-13 | 1.0.2   | Gemini     | Added missing 'import argparse' for type hints.
# 2025-05-13 | 1.0.3   | Gemini     | Modified parse_devices_input to recursively handle 'file:' prefix within list items and pass logger.
# 2025-05-14 | 1.0.4   | Gemini     | Corrected recursion in parse_devices_input to prevent over-splitting of plain strings and ensure file paths are processed correctly from various input structures.

import logging
import json
import os
import sys
import argparse # For type hinting argparse.Namespace
from typing import Dict, List, Optional, Tuple, Any, Callable

# Get logger for this module. It will use the configuration set up by the main script.
module_logger = logging.getLogger(__name__)


def setup_logger(debug: bool = False, log_file_path: Optional[str] = None, log_level=logging.INFO):
    """
    Configures the root logger for the script.
    """
    if logging.root.hasHandlers():
        logging.root.handlers.clear()

    level = logging.DEBUG if debug else log_level
    formatter_str = '%(asctime)s - %(levelname)s - %(name)s - %(funcName)s - %(message)s' if debug \
                    else '%(asctime)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(formatter_str)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level) # Set level on handler

    root_logger = logging.getLogger()
    root_logger.setLevel(level) # Set overall minimum level
    root_logger.addHandler(console_handler)

    if log_file_path:
        try:
            file_handler = logging.FileHandler(log_file_path, mode='a')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(level) # Set level on file handler
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
    # Use module_logger for utility function's own logging
    current_logger = module_logger if module_logger.hasHandlers() else logging.getLogger(__name__)

    if config_data is None:
        current_logger.debug(f"Config data is None, returning default for section '{section_name}'.")
        return default_value
    section_data = config_data.get(section_name, default_value)
    if section_data is default_value:
        if section_name not in config_data:
             current_logger.debug(f"Config section '{section_name}' not found, returning default value.")
    else:
         current_logger.debug(f"Successfully retrieved config section '{section_name}'.")
    return section_data


def parse_devices_input(devices_input: Any, logger_instance: logging.Logger) -> List[str]:
    """
    Parses the raw 'devices' input value into a flat list of unique string identifiers.
    Handles:
    - Direct string: "id1,id2,id3"
    - Single string identifier: "dns.name.com"
    - List: ["id1", "file:path/to/devices.txt", "id2,id3", "dns.name.com"]
    - "file:" prefix in strings to load identifiers from a file.
      The file itself can have one identifier per line or comma-separated identifiers per line.
    """
    collected_identifiers: List[str] = []

    if isinstance(devices_input, str):
        stripped_input = devices_input.strip()
        if not stripped_input: # Empty string after strip
            pass
        elif stripped_input.lower().startswith("file:"):
            file_path = stripped_input[len("file:"):]
            logger_instance.debug(f"Input string is a file path: '{file_path}'. Reading file.")
            collected_identifiers.extend(read_file_list(file_path, logger_instance))
        else:
            # It's a non-empty string, not a file path. Treat as comma-separated identifiers.
            # These are considered final identifiers from *this specific string*.
            logger_instance.debug(f"Input string is direct CSV or single ID: '{stripped_input}'. Splitting by comma.")
            collected_identifiers.extend([item.strip() for item in stripped_input.split(',') if item.strip()])
    elif isinstance(devices_input, list):
        logger_instance.debug(f"Input is a list. Processing {len(devices_input)} items recursively.")
        for item_in_list in devices_input:
            # Recursively call parse_devices_input for each item.
            # This ensures that if an item is "file:path.csv" or "id1,id2", it's handled correctly.
            collected_identifiers.extend(parse_devices_input(item_in_list, logger_instance))
    elif isinstance(devices_input, (int, float)):
        logger_instance.debug(f"Input is a number: {devices_input}. Converting to string.")
        num_str = str(devices_input).strip()
        if num_str: collected_identifiers.append(num_str)
    elif devices_input is not None:
        logger_instance.warning(f"Invalid data type for 'devices' input item: {type(devices_input)} ('{devices_input}'). Expected string, list, int, or float.")

    # Deduplicate while preserving order (Python 3.7+)
    seen = set()
    unique_identifiers = [x for x in collected_identifiers if not (x in seen or seen.add(x))]
    
    if len(collected_identifiers) != len(unique_identifiers):
        logger_instance.debug(f"Removed {len(collected_identifiers) - len(unique_identifiers)} duplicate identifiers. Final count: {len(unique_identifiers)}")
    return unique_identifiers


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
                if not stripped_line or stripped_line.startswith('#'):
                    continue
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
            logger_instance.debug(f"Collected '{dict_key_name}' from CLI arg '--{cli_arg_name.replace('_', '-')}' = '{cli_value}'.")
    config_section = get_config_section(config_data, config_section_name, {})
    all_potential_keys = required_keys.union(set(cli_arg_map.values()))
    for key in all_potential_keys:
         if key not in creds_dict and key in config_section:
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
    cli_arg_name: str,
    config_section_name: str,
    item_validator_func: Callable[[Dict, str], Tuple[bool, List[str]]],
    logger_instance: logging.Logger
) -> Tuple[List[Dict], List[Tuple[Any, List[str], str]]]:
    raw_items_with_source: List[Tuple[Dict, str]] = []
    parsing_errors_info: List[Tuple[Any, List[str], str]] = []
    logger_instance.debug(f"Collecting list items from CLI '--{cli_arg_name}' and config '{config_section_name}'...")
    cli_arg_values = getattr(args, cli_arg_name, []) or []
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
    config_section_data = get_config_section(config_data, config_section_name, [])
    if isinstance(config_section_data, list):
        if config_section_data: logger_instance.debug(f"Found {len(config_section_data)} item(s) in config '{config_section_name}'.")
        for i, item_data in enumerate(config_section_data):
            if isinstance(item_data, dict):
                raw_items_with_source.append((item_data, f"config '{config_section_name}', index {i}"))
            else:
                parsing_errors_info.append((item_data, ["Item in config list is not a dictionary."], f"config '{config_section_name}', index {i}"))
    elif config_section_data is not None:
         logger_instance.warning(f"Config section '{config_section_name}' is not a list. Skipping.")
    valid_items: List[Dict] = []
    invalid_item_details: List[Tuple[Any, List[str], str]] = list(parsing_errors_info)
    if raw_items_with_source:
        logger_instance.debug(f"Validating {len(raw_items_with_source)} collected items...")
        for item_dict, source_info in raw_items_with_source:
            is_item_valid, item_errors = item_validator_func(item_dict, source_info)
            if is_item_valid:
                valid_items.append(item_dict)
            else:
                invalid_item_details.append((item_dict, item_errors, source_info))
    return valid_items, invalid_item_details
