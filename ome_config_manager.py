#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OpenManage Enterprise (OME) Configuration Manager (v1.0.11).
Performs initial OME setup and/or individual configuration tasks.
NTP configuration now expects direct API keys in input.
"""

# __version__ = "1.0.10" # Previous Version
__version__ = "1.0.11" # Aligned NTP input keys to direct API keys.

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-15 | 1.0.10  | Gemini     | Removed local handle_static_group_creation, now imports and uses
#            |         |            | process_group_task from sg_group.py after normalizing tasks.
# 2025-05-15 | 1.0.11  | Gemini     | Updated NTP handling to expect direct API keys in input,
#            |         |            | aligning with constants v1.3.10 and input_validator v1.2.11.

import argparse
import sys
import logging
import json
import time 
import copy 

from typing import Dict, List, Optional, Tuple, Any, Union

import utils
import constants # Expecting v1.3.10 or later
import input_validator # Expecting v1.2.11 or later
import ome_client 
import ad_manager 
import sg_group   

logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------
# Configuration Task Functions
#------------------------------------------------------------------------------

def handle_ad_configuration(ome_client_instance: ome_client.OmeClient,
                            ad_provider_base_input: Optional[Dict], 
                            logger_instance: logging.Logger) -> Tuple[bool, Optional[int]]:
    if not ad_provider_base_input:
        logger_instance.info("No AD Provider base configuration data provided. Skipping AD setup.")
        return True, None 
    provider_name_from_input = ad_provider_base_input.get('Name')
    if not provider_name_from_input: 
        logger_instance.error("AD Provider 'Name' is missing in the configuration data. Skipping AD setup.")
        return False, None
    logger_instance.info(f"--- Configuring AD Provider: '{provider_name_from_input}' ---")
    config_payload_for_api = {}
    for key in constants.AD_PROVIDER_PAYLOAD_REQUIRED_KEYS: 
        if key not in ad_provider_base_input:
            logger_instance.error(f"Required key '{key}' for AD provider config missing in input for '{provider_name_from_input}'. Skipping.")
            return False, None
        config_payload_for_api[key] = ad_provider_base_input[key]
    for key in constants.AD_PROVIDER_PAYLOAD_OPTIONAL_KEYS: 
        if key in ad_provider_base_input and ad_provider_base_input[key] is not None:
            config_payload_for_api[key] = ad_provider_base_input[key]
    if config_payload_for_api.get('ServerType') != "MANUAL":
        config_payload_for_api['ServerType'] = "MANUAL"
    if 'CertificateValidation' not in config_payload_for_api: 
        config_payload_for_api['CertificateValidation'] = False 
    if 'CertificateFile' not in config_payload_for_api: 
        config_payload_for_api['CertificateFile'] = ""
    config_payload_for_api.pop('SearchUsername', None) 
    config_payload_for_api.pop('SearchPassword', None)
    logger_instance.debug(f"Payload for AD Provider configuration API call: {config_payload_for_api}")
    provider_id = ome_client_instance.configure_ad_provider(config_payload_for_api) # type: ignore
    if provider_id is None:
        logger_instance.error(f"Failed to configure AD provider '{provider_name_from_input}'.")
        return False, None
    logger_instance.info(f"AD Provider '{provider_name_from_input}' configured/updated successfully. Provider ID: {provider_id}")
    
    search_username = ad_provider_base_input.get('SearchUsername', ad_provider_base_input.get('UserName'))
    search_password = ad_provider_base_input.get('SearchPassword', ad_provider_base_input.get('Password'))
    if not search_username or search_password is None:
        logger_instance.warning(f"AD search credentials not found in input for provider '{provider_name_from_input}'. Skipping connection test.")
        return True, provider_id 
    
    test_connection_payload = {}
    for key in constants.AD_TEST_CONNECTION_PAYLOAD_REQUIRED_KEYS:
        if key == 'UserName': test_connection_payload[key] = search_username
        elif key == 'Password': test_connection_payload[key] = search_password
        elif key in ad_provider_base_input: test_connection_payload[key] = ad_provider_base_input[key]
        elif key == 'CertificateValidation': test_connection_payload[key] = False 
        elif key == 'CertificateFile': test_connection_payload[key] = ""       
        else:
            logger_instance.error(f"Required key '{key}' for TestADConnection missing from input for '{provider_name_from_input}'. Skipping test.")
            return True, provider_id 
    if test_connection_payload.get('ServerType') != "MANUAL": 
        test_connection_payload['ServerType'] = "MANUAL"
    logger_instance.info(f"Validating connection for AD Provider '{provider_name_from_input}' (ID: {provider_id}) using search credentials...")
    logger_instance.debug(f"Payload for TestADConnection: {test_connection_payload}")
    test_success = ome_client_instance.test_ad_provider_connection(test_connection_payload) # type: ignore
    if test_success: logger_instance.info(f"AD Provider '{provider_name_from_input}' (ID: {provider_id}) connection test successful.")
    else: logger_instance.error(f"AD Provider '{provider_name_from_input}' (ID: {provider_id}) connection test failed.")
    logger_instance.info(f"--- Finished AD Provider Configuration for '{provider_name_from_input}' ---")
    return test_success, provider_id


def handle_ntp_configuration(ome_client_instance: ome_client.OmeClient,
                             ntp_api_payload: Optional[Dict], # Expects direct API keys after validation
                             logger_instance: logging.Logger) -> bool:
    """Configures NTP servers in OME using a payload with direct API keys."""
    if not ntp_api_payload:
        logger_instance.info("No NTP configuration data provided. Skipping NTP setup.")
        return True 

    logger_instance.info("--- Configuring NTP Servers ---")
    
    # Input 'ntp_api_payload' is now expected to have direct API keys like 'EnableNTP', 'PrimaryNTPAddress'.
    # Validation should have been done by input_validator.validate_ntp_config_payload_specific.

    # Basic check for essential keys (should be covered by validator)
    if not isinstance(ntp_api_payload.get("EnableNTP"), bool): 
        logger_instance.error("'EnableNTP' key is missing or not a boolean in NTP config. Skipping.")
        return False
    if ntp_api_payload.get("EnableNTP") and not ntp_api_payload.get("PrimaryNTPAddress"):
        logger_instance.error("'PrimaryNTPAddress' is required if EnableNTP is true. Skipping.")
        return False
    if ntp_api_payload.get("EnableNTP") and not ntp_api_payload.get("TimeZone"):
        logger_instance.error("'TimeZone' is required if EnableNTP is true. Skipping.")
        return False

    # The payload is already structured for the API.
    # We might still want to clean out any truly null optional values if the API is strict,
    # but constants.NTP_CONFIG_OPTIONAL_KEYS helps the validator know what's okay to be missing.
    payload_to_send = {k: v for k, v in ntp_api_payload.items() if v is not None or k in constants.NTP_CONFIG_REQUIRED_KEYS}
    # Ensure EnableNTP is definitely in the payload being sent, even if false and other optionals are None
    if "EnableNTP" not in payload_to_send:
        payload_to_send["EnableNTP"] = ntp_api_payload.get("EnableNTP", False)


    logger_instance.info(f"Setting NTP configuration with API payload: {payload_to_send}")
    success = ome_client_instance.set_ntp_configuration(payload_to_send) # type: ignore
    if success: 
        logger_instance.info("NTP configuration update request sent successfully.")
    else: 
        logger_instance.error("Failed to configure NTP.")
    logger_instance.info("--- Finished NTP Server Configuration ---")
    return success

# ... (handle_dns_configuration, handle_csr_generation, handle_plugin_configuration, 
#      handle_static_group_creation, and AD import functions remain the same as v1.0.9) ...

def handle_dns_configuration(ome_client_instance: ome_client.OmeClient,
                             dns_servers_input: Optional[List[str]], 
                             logger_instance: logging.Logger,
                             max_wait_seconds: int = 300, poll_interval: int = 15) -> bool:
    if not dns_servers_input:
        logger_instance.info("No DNS server list provided. Skipping DNS setup.")
        return True
    logger_instance.info("--- Configuring DNS Servers ---")
    preferred_dns = dns_servers_input[0]
    alternate_dns = dns_servers_input[1] if len(dns_servers_input) > 1 else ""
    if len(dns_servers_input) > 2:
        logger_instance.warning(f"More than 2 DNS servers provided. Using Preferred: {preferred_dns}, Alternate: {alternate_dns}")
    logger_instance.info(f"Attempting to set DNS servers on primary adapter to Preferred: {preferred_dns}, Alternate: {alternate_dns}")
    initiated, job_id = ome_client_instance.configure_network_adapter_dns(preferred_dns, alternate_dns) # type: ignore
    if not initiated:
        logger_instance.error("Failed to initiate DNS server configuration change.")
        return False
    if not job_id:
        logger_instance.error("DNS configuration initiated, but no job ID returned. Cannot monitor status.")
        return False 
    logger_instance.info(f"DNS configuration job submitted. Job ID: {job_id}. Monitoring status (max {max_wait_seconds}s)...")
    start_time = time.time()
    while time.time() - start_time < max_wait_seconds:
        try:
            job_details = ome_client_instance.get_job_details(job_id) # type: ignore
            if not job_details:
                logger_instance.warning(f"Could not retrieve status for DNS job {job_id}. Retrying in {poll_interval}s...")
                time.sleep(poll_interval); continue
            status_name = job_details.get("JobStatus", {}).get("Name", "Unknown").lower()
            last_run_status_name = job_details.get("LastRunStatus", {}).get("Name", "Unknown").lower()
            logger_instance.info(f"DNS config Job {job_id} status: '{status_name}' (Last Run: '{last_run_status_name}')")
            if status_name == "completed" or last_run_status_name == "completed":
                logger_instance.info(f"DNS configuration job {job_id} reported as completed successfully.")
                return True
            elif status_name in ["failed", "error", "aborted"] or \
                 last_run_status_name in ["failed", "error", "aborted", "downloadfailed"]:
                error_message = f"Job State: {status_name}, Last Run State: {last_run_status_name}."
                logger_instance.error(f"DNS configuration job {job_id} failed. {error_message}")
                return False
        except Exception as e: logger_instance.error(f"Error retrieving status for DNS job {job_id}: {e}", exc_info=True)
        time.sleep(poll_interval)
    logger_instance.error(f"DNS configuration job {job_id} timed out after {max_wait_seconds} seconds.")
    return False

def handle_csr_generation(ome_client_instance: ome_client.OmeClient,
                          csr_user_input: Optional[Dict], 
                          logger_instance: logging.Logger) -> bool:
    if not csr_user_input:
        logger_instance.info("No CSR details provided. Skipping CSR generation.")
        return True
    logger_instance.info("--- Generating CSR (Certificate Signing Request) ---")
    api_payload = {
        "DistinguishedName": csr_user_input.get("common_name"), "DepartmentName": csr_user_input.get("organizational_unit"),
        "BusinessName": csr_user_input.get("organization"), "Locality": csr_user_input.get("locality"),
        "State": csr_user_input.get("state_or_province"), "Country": csr_user_input.get("country_code"),
        "Email": csr_user_input.get("email_address"), "KeySize": str(csr_user_input.get("key_size", "4096")), 
        "San": csr_user_input.get("subject_alternative_names_str") 
    }
    api_payload_cleaned = {k: v for k, v in api_payload.items() if v is not None}
    if "KeySize" not in api_payload_cleaned and "key_size" in csr_user_input : 
         api_payload_cleaned["KeySize"] = str(csr_user_input["key_size"])
    required_api_keys = {"DistinguishedName", "DepartmentName", "BusinessName", "Locality", "State", "Country", "Email", "KeySize"}
    missing_api_keys = required_api_keys - set(api_payload_cleaned.keys())
    if missing_api_keys:
        logger_instance.error(f"Missing required fields for CSR API payload: {missing_api_keys}. Skipping.")
        return False
    logger_instance.info(f"Requesting CSR generation with API payload: {api_payload_cleaned}")
    csr_pem = ome_client_instance.generate_csr(api_payload_cleaned) # type: ignore
    if csr_pem:
        logger_instance.info("CSR generated successfully.")
        logger_instance.info("CSR (first 100 chars): " + csr_pem[:100].replace("\n", "\\n") + "...")
        logger_instance.debug(f"Full generated CSR:\n{csr_pem}")
        cn_for_filename = api_payload_cleaned.get('DistinguishedName', 'ome_csr').replace('.', '_').replace('*','_wildcard_')
        csr_file_name = f"{cn_for_filename}.csr"
        try:
            with open(csr_file_name, 'w') as f: f.write(csr_pem)
            logger_instance.info(f"CSR saved to file: {csr_file_name}")
        except IOError as e: logger_instance.error(f"Failed to save CSR to file '{csr_file_name}': {e}")
        return True
    else: logger_instance.error("Failed to generate CSR."); return False

def handle_plugin_configuration(ome_client_instance: ome_client.OmeClient,
                                plugin_tasks_input: Optional[List[Dict]], 
                                logger_instance: logging.Logger) -> bool:
    if not plugin_tasks_input:
        logger_instance.info("No plugin configuration tasks provided. Skipping plugin management.")
        return True
    logger_instance.info("--- Configuring/Managing Plugins ---")
    payload = {"Plugins": plugin_tasks_input} 
    logger_instance.info(f"Submitting plugin actions with payload: {json.dumps(payload, indent=2)[:500]}...")
    success = ome_client_instance.update_console_plugins(payload) # type: ignore
    if success: logger_instance.info("Plugin actions request submitted successfully.")
    else: logger_instance.error("Failed to submit plugin actions request.")
    logger_instance.info("--- Finished Plugin Management ---")
    return success

# Main function in ome_config_manager.py
def main():
    # ... (Argparse setup remains the same as v1.0.9, ensuring --ntp-payload help text is generic)
    # Example for NTP CLI arg help text:
    # grp_ntp.add_argument(f'--{constants.NTP_PAYLOAD_CLI_ARG_NAME.replace("_", "-")}', dest='ntp_payload_cli', metavar='JSON_STRING', 
    #                      help="JSON string for NTP config (using direct API keys like 'EnableNTP', 'PrimaryNTPAddress', 'TimeZone', etc.). Used if --initial-setup or --run-ntp-config.")
    # ...

    # In main(), when calling the validator for NTP:
    # ...
    # if run_all or args.run_ntp_config:
    #     logger.info("--- Preparing for NTP Configuration ---")
    #     ntp_api_payload_input = utils.get_single_input(args.ntp_payload_cli, config, constants.NTP_CONFIG_SECTION, logger, is_json_string_cli=True)
    #     if ntp_api_payload_input:
    #         # Validate using the validator that expects direct API keys
    #         is_valid, errors = input_validator.validate_ntp_config_payload_specific(ntp_api_payload_input, "NTP Config Input")
    #         if is_valid:
    #             if not handle_ntp_configuration(ome_client_instance, ntp_api_payload_input, logger):
    #                 overall_script_success = False
    #         else:
    #             logger.error(f"Invalid NTP configuration provided: {errors}")
    #             overall_script_success = False
    #     elif run_all or args.run_ntp_config:
    #          logger.warning("NTP configuration requested but no payload data found. Skipping.")
    # ...

# For brevity, only the changed handle_ntp_configuration and a snippet of main's calling logic are shown.
# The rest of the file (other handle_* functions, full main, AD import calls) would be as in v1.0.9.
# The full, updated main() function would integrate this change.
# The following is the full main() function from v1.0.9 with the NTP part updated.

    parser = argparse.ArgumentParser(
        description="OME Configuration Manager: Initial Setup & Individual Tasks.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    grp_behavior = parser.add_argument_group('Script Behavior Modes')
    grp_behavior.add_argument('--initial-setup', action='store_true', help="Run all configured initial setup steps AND AD Group Imports unless explicitly skipped by another flag for AD imports.")
    grp_behavior.add_argument('--run-ad-config', action='store_true', help="Run AD Provider configuration and validation.")
    grp_behavior.add_argument('--run-ntp-config', action='store_true', help="Run NTP server configuration.")
    grp_behavior.add_argument('--run-dns-config', action='store_true', help="Run DNS server configuration.")
    grp_behavior.add_argument('--run-csr-generation', action='store_true', help="Run CSR generation.")
    grp_behavior.add_argument('--run-plugin-config', action='store_true', help="Run plugin configuration tasks.")
    grp_behavior.add_argument('--run-static-group-creation', action='store_true', help="Run static group creation tasks.")
    grp_behavior.add_argument('--run-ad-group-import', action='store_true', help="Run AD group import tasks.")

    grp_ome = parser.add_argument_group('OME Connection Details (Required for all operations)')
    grp_ome.add_argument('--ome-url', metavar='URL', help="URL for OME")
    grp_ome.add_argument('--username', metavar='USER', help="OME username")
    grp_ome.add_argument('--password', metavar='PASS', help="OME password")

    grp_ad_provider = parser.add_argument_group('AD Provider Details (Used by AD Config & AD Group Import)')
    grp_ad_provider.add_argument(f'--{constants.AD_PROVIDER_FIND_CLI_MAP.get("ad_provider_name", "ad-provider-name").replace("_","-")}', dest='ad_provider_name', metavar='NAME', help="Name for AD provider in OME.")
    grp_ad_provider.add_argument(f'--{constants.AD_PROVIDER_CONFIGURE_PARAMETER_CLI_ARG_NAME.replace("_", "-")}', dest='ad_configure_parameter_cli', metavar='JSON_STRING', help="JSON for full AD provider config (payload).")
    grp_ad_provider.add_argument(f'--{constants.AD_CRED_CLI_MAP.get("UserName", "ad-search-username").replace("_","-")}', dest='ad_search_username', metavar='USER', help="AD username for OME to search AD.")
    grp_ad_provider.add_argument(f'--{constants.AD_CRED_CLI_MAP.get("Password", "ad-search-password").replace("_","-")}', dest='ad_search_password', metavar='PASS', help="AD password for OME to search AD.")

    grp_ntp = parser.add_argument_group('NTP Configuration Details')
    # Help text updated to reflect direct API keys
    ntp_help = "JSON string for NTP config (using direct API keys like 'EnableNTP', 'PrimaryNTPAddress', 'TimeZone', 'SecondaryNTPAddress1', 'SecondaryNTPAddress2'). Used if --initial-setup or --run-ntp-config."
    grp_ntp.add_argument(f'--{constants.NTP_PAYLOAD_CLI_ARG_NAME.replace("_", "-")}', dest='ntp_payload_cli', metavar='JSON_STRING', help=ntp_help)

    grp_dns = parser.add_argument_group('DNS Configuration Details')
    grp_dns.add_argument(f'--{constants.DNS_SERVERS_CLI_ARG_NAME.replace("_", "-")}', dest='dns_servers_cli', metavar='"S1,S2"', help="Comma-separated list of DNS server IPs.")

    grp_csr = parser.add_argument_group('CSR Generation Details')
    grp_csr.add_argument(f'--{constants.CSR_DETAILS_PAYLOAD_CLI_ARG_NAME.replace("_", "-")}', dest='csr_payload_cli', metavar='JSON_STRING', help="JSON for CSR details (user-friendly keys).")

    grp_plugins = parser.add_argument_group('Plugin Configuration Tasks')
    grp_plugins.add_argument(f'--{constants.PLUGIN_ACTION_TASK_CLI_ARG_NAME.replace("_", "-")}', dest='plugin_action_tasks_cli', action='append', metavar='JSON_STRING', help="JSON for one plugin task ('{\"Id\":\"GUID\"...}'). Multi-use.")

    grp_static_groups = parser.add_argument_group('Static Group Creation Tasks')
    grp_static_groups.add_argument(f'--{constants.STATIC_GROUP_CLI_ARG_NAME}', dest='static_group_tasks_cli', action='append', metavar='JSON_STRING', help="JSON for one static group ('{\"group_name\":\"N\"...}'). Multi-use.")
    
    grp_ad_import = parser.add_argument_group('AD Group Import Tasks')
    ad_import_help = (f"JSON for AD import task (keys: group_name, role, scope). Default role: {constants.DEFAULT_AD_IMPORT_ROLE}. Multi-use.")
    grp_ad_import.add_argument(f'--{constants.AD_IMPORT_GROUP_CLI_ARG_NAME}', dest='ad_import_tasks_cli', action='append', help=ad_import_help, metavar='JSON_STRING')
    
    grp_general = parser.add_argument_group('General Configuration & Logging')
    grp_general.add_argument('--config', help='Path to JSON config file for all settings.', metavar='FILE_PATH')
    grp_general.add_argument('--debug', action='store_true', help="Enable debug level logging.")
    grp_general.add_argument('--log-file', metavar='LOG_FILE_PATH', help="Path to a file for logging output.")
    args = parser.parse_args()

    utils.setup_logger(debug=args.debug, log_file_path=args.log_file) 
    logger.info(f"OME Configuration Manager script started (Version: {__version__}).")
    logger.debug(f"Parsed arguments: {args}")

    config: Optional[Dict] = None
    if args.config:
        config = utils.load_config(args.config, logger)
        if config is None: logger.fatal(f"Failed to load config '{args.config}'. Exiting."); sys.exit(1)

    ome_creds, is_ome_creds_valid = utils.collect_and_validate_credentials(
        args, config, constants.OME_AUTH_REQUIRED_KEYS, constants.OME_CRED_CONFIG_SECTION, 
        constants.OME_CLI_CRED_MAP, input_validator.validate_ome_credentials_specific, logger
    )
    if not is_ome_creds_valid: logger.fatal("Invalid OME credentials. Exiting."); sys.exit(1)
    
    ome_client_instance: Optional[ome_client.OmeClient] = None
    try:
        ome_client_instance = ome_client.OmeClient(ome_creds['url'], ome_creds['username'], ome_creds['password']) 
        ome_client_instance.authenticate()
        logger.info("Successfully authenticated with OME.")
    except Exception as e: logger.fatal(f"Failed OME client setup/auth: {e}", exc_info=args.debug); sys.exit(1)

    run_all = args.initial_setup
    any_individual_task_run = any([args.run_ad_config, args.run_ntp_config, args.run_dns_config,
                                   args.run_csr_generation, args.run_plugin_config,
                                   args.run_static_group_creation, args.run_ad_group_import])
    if not run_all and not any_individual_task_run:
        logger.info("No specific operation requested and --initial-setup not used. Use --help. Exiting.")
        sys.exit(0)

    overall_script_success = True
    ad_provider_id_from_config_step: Optional[int] = None 

    # --- 1. AD Configuration ---
    if run_all or args.run_ad_config:
        logger.info("--- Preparing for AD Provider Configuration ---")
        ad_provider_input = utils.get_single_input(
            args.ad_configure_parameter_cli, config, constants.AD_CONFIG_SECTION, logger, is_json_string_cli=True 
        )
        if ad_provider_input:
            # TODO: Call input_validator.validate_ad_provider_payload_specific(ad_provider_input, ...)
            if 'Name' not in ad_provider_input and args.ad_provider_name:
                ad_provider_input['Name'] = args.ad_provider_name
            if not ad_provider_input.get('Name'):
                logger.error("AD Provider 'Name' missing for configuration. Skipping AD setup.")
                overall_script_success = False
            else:
                success, prov_id = handle_ad_configuration(ome_client_instance, ad_provider_input, logger)
                if not success: overall_script_success = False
                if prov_id is not None: ad_provider_id_from_config_step = prov_id
        elif run_all or args.run_ad_config:
             logger.warning("AD configuration requested but no payload data found. Skipping.")

    # --- 2. NTP Configuration ---
    if run_all or args.run_ntp_config:
        logger.info("--- Preparing for NTP Configuration ---")
        # Input now expects direct API keys (EnableNTP, PrimaryNTPAddress, etc.)
        ntp_api_payload_input = utils.get_single_input(args.ntp_payload_cli, config, constants.NTP_CONFIG_SECTION, logger, is_json_string_cli=True)
        if ntp_api_payload_input:
            # Validate using the validator that expects direct API keys
            is_valid, errors = input_validator.validate_ntp_config_payload_specific(ntp_api_payload_input, "NTP Config Input")
            if is_valid:
                if not handle_ntp_configuration(ome_client_instance, ntp_api_payload_input, logger):
                    overall_script_success = False
            else:
                logger.error(f"Invalid NTP configuration provided: {errors}")
                overall_script_success = False
        elif run_all or args.run_ntp_config:
             logger.warning("NTP configuration requested but no payload data found. Skipping.")

    # --- 3. DNS Configuration ---
    if run_all or args.run_dns_config:
        logger.info("--- Preparing for DNS Configuration ---")
        dns_servers_list_cli = []
        if args.dns_servers_cli:
            dns_servers_list_cli = [s.strip() for s in args.dns_servers_cli.split(',') if s.strip()]
        dns_config_from_file = utils.get_config_section(config, constants.DNS_SERVERS_CONFIG_SECTION, {})
        dns_servers_list_file = dns_config_from_file.get("servers", []) if isinstance(dns_config_from_file, dict) else []
        if not isinstance(dns_servers_list_file, list): dns_servers_list_file = [] 
        dns_servers_to_use = dns_servers_list_cli if dns_servers_list_cli else dns_servers_list_file
        if dns_servers_to_use:
            # TODO: Call input_validator.validate_dns_servers_list_specific(dns_servers_to_use, ...)
            if not handle_dns_configuration(ome_client_instance, dns_servers_to_use, logger):
                overall_script_success = False
        elif run_all or args.run_dns_config:
            logger.warning("DNS configuration requested but no DNS servers provided. Skipping.")

    # --- 4. CSR Generation ---
    if run_all or args.run_csr_generation:
        logger.info("--- Preparing for CSR Generation ---")
        csr_user_input = utils.get_single_input(args.csr_payload_cli, config, constants.CSR_CONFIG_SECTION, logger, is_json_string_cli=True)
        if csr_user_input:
            # TODO: Call input_validator.validate_csr_user_input_specific(csr_user_input, ...)
            if not handle_csr_generation(ome_client_instance, csr_user_input, logger): 
                overall_script_success = False
        elif run_all or args.run_csr_generation:
            logger.warning("CSR generation requested but no details data found. Skipping.")

    # --- 5. Plugin Configuration ---
    if run_all or args.run_plugin_config:
        logger.info("--- Preparing for Plugin Configuration ---")
        valid_tasks, invalid_details = utils.collect_and_validate_list_inputs(
            args, config, constants.PLUGIN_ACTION_TASK_CLI_ARG_NAME, constants.PLUGIN_TASKS_CONFIG_SECTION,
            input_validator.validate_plugin_action_task_specific, logger 
        )
        if invalid_details: 
            logger.warning(f"Skipping {len(invalid_details)} invalid plugin tasks.")
            for item, errs, src in invalid_details: logger.error(f"  Invalid plugin task from {src}: {item} -> {errs}")
        if valid_tasks:
            if not handle_plugin_configuration(ome_client_instance, valid_tasks, logger):
                overall_script_success = False
        elif run_all or args.run_plugin_config:
            logger.info("Plugin configuration requested but no valid tasks found. Skipping.")

    # --- 6. Static Group Creation ---
    if run_all or args.run_static_group_creation:
        logger.info("--- Preparing for Static Group Creation ---")
        valid_raw_sg_tasks, invalid_sg_details = utils.collect_and_validate_list_inputs(
            args, config, constants.STATIC_GROUP_CLI_ARG_NAME, constants.STATIC_GROUP_CONFIG_SECTION,
            input_validator.validate_static_group_definition_specific, logger 
        )
        if invalid_sg_details:
            logger.warning(f"Skipping {len(invalid_sg_details)} invalid static group creation tasks.")
            for item, errs, src in invalid_sg_details: logger.error(f"  Invalid static group task from {src}: {item} -> {errs}")
        if valid_raw_sg_tasks:
            normalized_sg_tasks: List[Dict] = []
            for raw_group_dict in valid_raw_sg_tasks:
                group_task_for_sg_module = {
                    "group_name": raw_group_dict['group_name'], 
                    "create": raw_group_dict.get('create', constants.DEFAULT_CREATE_FLAG),
                    "parent_group_name": raw_group_dict.get('parent_group', constants.DEFAULT_PARENT_GROUP),
                    "devices_raw": [], 
                    "identifier_type": None,
                }
                if 'devices' in raw_group_dict and raw_group_dict.get('devices') is not None: 
                    group_task_for_sg_module['identifier_type'] = raw_group_dict.get('identifier_type') 
                    group_task_for_sg_module['devices_raw'] = utils.parse_devices_input(raw_group_dict['devices'], logger)
                normalized_sg_tasks.append(group_task_for_sg_module)
            if normalized_sg_tasks:
                logger.info(f"Processing {len(normalized_sg_tasks)} static group tasks using sg_group.process_group_task...")
                current_sg_success = True
                for sg_task_item in normalized_sg_tasks:
                    try:
                        sg_group.process_group_task(ome_client_instance, sg_task_item, logger)
                    except Exception as e:
                        logger.error(f"Error processing static group task '{sg_task_item.get('group_name')} via sg_group.py: {e}", exc_info=True)
                        current_sg_success = False 
                if not current_sg_success: overall_script_success = False
            else: 
                 logger.info("No static group tasks to process after normalization.")
        elif run_all or args.run_static_group_creation: 
            logger.info("Static group creation requested but no valid tasks found. Skipping.")
            
    # --- 7. AD Group Import ---
    if run_all or args.run_ad_group_import:
        logger.info("--- Preparing for AD Group Import ---")
        ad_provider_id_for_import_final = ad_provider_id_from_config_step
        ad_provider_name_for_import_final = args.ad_provider_name or \
            (config.get(constants.AD_CONFIG_SECTION, {}) if config else {}).get('Name')

        if ad_provider_id_for_import_final is None and ad_provider_name_for_import_final:
            logger.info(f"AD Provider ID not available from AD config step. Finding by name '{ad_provider_name_for_import_final}' for import...")
            try:
                pid_raw = ome_client_instance.get_ad_provider_id_by_name(ad_provider_name_for_import_final)
                if pid_raw is not None: ad_provider_id_for_import_final = int(pid_raw)
                else: logger.error(f"AD Provider '{ad_provider_name_for_import_final}' not found for import.")
            except Exception as e: logger.error(f"Error finding AD Provider '{ad_provider_name_for_import_final}': {e}")
        
        ad_config_section_data_for_import = config.get(constants.AD_CONFIG_SECTION, {}) if config else {}
        search_user_for_import = args.ad_search_username or \
                                 ad_config_section_data_for_import.get('SearchUsername', ad_config_section_data_for_import.get('UserName')) 
        search_pass_for_import = args.ad_search_password if args.ad_search_password is not None else \
                                 ad_config_section_data_for_import.get('SearchPassword', ad_config_section_data_for_import.get('Password'))

        if ad_provider_id_for_import_final is not None and search_user_for_import and search_pass_for_import is not None:
            valid_ad_import_tasks, invalid_ad_tasks = utils.collect_and_validate_list_inputs(
                args, config, constants.AD_IMPORT_GROUP_CLI_ARG_NAME, 
                constants.AD_IMPORT_GROUP_CONFIG_SECTION, input_validator.validate_ad_import_task_specific, logger
            )
            if invalid_ad_tasks: 
                logger.warning(f"Skipping {len(invalid_ad_tasks)} invalid AD import tasks.")
                for item, errs, src in invalid_ad_tasks: logger.error(f"  Invalid AD import task from {src}: {item} -> {errs}")

            if valid_ad_import_tasks:
                normalized_tasks = []
                for task_dict in valid_ad_import_tasks: 
                    normalized_tasks.append({
                        "group_name": task_dict["group_name"],
                        "role": task_dict.get("role", constants.DEFAULT_AD_IMPORT_ROLE), 
                        "scope": task_dict.get("scope") 
                    })
                if not ad_manager.run_ad_import_workflow( 
                    ome_client_instance, ad_provider_id_for_import_final,
                    ad_provider_name_for_import_final or f"ID_{ad_provider_id_for_import_final}",
                    search_user_for_import, search_pass_for_import,
                    normalized_tasks, logger):
                    overall_script_success = False
            elif run_all or args.run_ad_group_import:
                 logger.info("AD Group Import requested but no valid tasks found. Skipping.")
        elif run_all or args.run_ad_group_import:
            logger.warning("AD Group Import requested but AD Provider ID or search credentials could not be determined. Skipping.")

    # --- Finalization ---
    if ome_client_instance:
        try: ome_client_instance.logout(); logger.info("Successfully logged out from OME.")
        except Exception as e: logger.warning(f"Error during OME logout: {e}", exc_info=args.debug)
    
    exit_code = 0 if overall_script_success else 1
    logger.info(f"OME Configuration Manager script finished. Overall Success: {overall_script_success}. Exit Code: {exit_code}.")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
