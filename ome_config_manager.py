#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OpenManage Enterprise (OME) Configuration Manager (v1.0.1).
Performs initial OME setup and/or individual configuration tasks including:
- AD Provider Configuration & Validation
- NTP Server Configuration
- DNS Server Configuration
- CSR Generation
- Plugin Management (Install/Update)
- Static Group Creation
- AD Group Import with Role/Scope assignment
"""

# __version__ = "1.0.0" # Previous Version
__version__ = "1.0.1" # Aligned with constants.py v1.3.2 (consolidated AD config, static group, and AD import constants)

# Modifications:
# Date       | Version | Author     | Description
# ---------- | ------- | ---------- | -----------
# ... (previous history) ...
# 2025-05-15 | 1.0.1   | Rahul Mehta     | Updated to use consolidated AD_CONFIG_SECTION from constants v1.3.2.
#            |         |            | Aligned static group and AD import task handling with constants v1.3.2.

import argparse
import sys
import logging
import json
import time # For job polling

from typing import Dict, List, Optional, Tuple, Any, Union

# Ensure these custom modules are available in the Python path
import utils
import constants # Expecting v1.3.2 or later
import input_validator # Expecting new validation functions to be added here
import ome_client # Expecting new methods to be added here

# Initialize logger for this module
logger = logging.getLogger(__name__)

# --- Conceptual OME Client Method Signatures (Reminder) ---
# class OmeClient:
#     def configure_ad_provider(self, ad_config_payload: Dict) -> Optional[int]: pass
#     def test_ad_provider_connection(self, test_payload: Dict) -> bool: pass # test_payload includes Provider ID
#     def set_ntp_configuration(self, ntp_payload: Dict) -> bool: pass
#     def configure_network_adapter_dns(self, preferred_dns: str, alternate_dns: Optional[str]) -> Tuple[bool, Optional[str]]: pass # Helper
#     def get_job_details(self, job_id: Union[str, int]) -> Optional[Dict]: pass
#     def update_console_plugins(self, plugins_action_payload: Dict) -> bool: pass
#     def create_static_group(self, name: str, description: Optional[str] = None, parent_id: Optional[int] = None) -> Optional[str]: pass # Returns group ID as str
#     def generate_csr(self, csr_payload: Dict) -> Optional[str]: pass
#     # ... and existing AD import related methods ...

#------------------------------------------------------------------------------
# Configuration Task Functions (Adapted from ad_manager.py and new)
#------------------------------------------------------------------------------

def handle_ad_configuration(ome_client_instance: ome_client.OmeClient,
                            ad_provider_full_config: Optional[Dict], # Validated full payload for AD provider
                            ad_search_creds: Dict, # Validated {'Username': ..., 'Password': ...} for TestConnection
                            logger_instance: logging.Logger) -> Tuple[bool, Optional[int]]:
    """Configures AD provider and validates connection. Returns (success, provider_id)."""
    if not ad_provider_full_config:
        logger_instance.info("No AD Provider configuration data provided. Skipping AD setup.")
        return True, None # True because no action was requested/failed

    # 'Name' is essential and should be validated by input_validator for ad_provider_full_config
    provider_name = ad_provider_full_config.get('Name')
    if not provider_name:
        logger_instance.error("AD Provider 'Name' is missing in the configuration data. Skipping AD setup.")
        return False, None

    logger_instance.info(f"--- Configuring AD Provider: '{provider_name}' ---")
    
    # Ensure ServerType is MANUAL as per prior requirement for the payload, if not already set
    if ad_provider_full_config.get('ServerType') != "MANUAL":
        logger_instance.info(f"Setting ServerType to 'MANUAL' for AD Provider '{provider_name}'.")
        ad_provider_full_config['ServerType'] = "MANUAL"
    
    # Default CertificateValidation if not provided, as API might require it
    if 'CertificateValidation' not in ad_provider_full_config:
        ad_provider_full_config['CertificateValidation'] = False # Or True, depending on desired default
    if 'CertificateFile' not in ad_provider_full_config: # API might require empty string if validation is true but no file
        ad_provider_full_config['CertificateFile'] = ""

    # configure_ad_provider in OME client handles the POST to /api/AccountService/ExternalAccountProvider/ADAccountProvider
    provider_id = ome_client_instance.configure_ad_provider(ad_provider_full_config) # type: ignore
    
    if provider_id is None:
        logger_instance.error(f"Failed to configure AD provider '{provider_name}'. No ID returned or error in client.")
        return False, None
    logger_instance.info(f"AD Provider '{provider_name}' configured/updated successfully. Provider ID: {provider_id}")

    if not ad_search_creds.get("Username") or not ad_search_creds.get("Password"):
        logger_instance.warning(f"AD search credentials (username/password) not provided for TestADConnection for provider '{provider_name}'. Skipping connection test.")
        logger_instance.info(f"--- Finished AD Provider Configuration for '{provider_name}' (connection test skipped) ---")
        return True, provider_id

    # Payload for TestADConnection
    test_payload = {
        "Id": provider_id,
        "UserName": ad_search_creds["Username"],
        "Password": ad_search_creds["Password"],
        "GroupDomain": ad_provider_full_config.get("GroupDomain", "") # From the main AD config
        # Add other fields if the TestADConnection API specifically requires them.
    }
    
    logger_instance.info(f"Validating connection for AD Provider '{provider_name}' (ID: {provider_id})...")
    test_success = ome_client_instance.test_ad_provider_connection(test_payload) # type: ignore # Pass full test_payload
    
    if test_success:
        logger_instance.info(f"AD Provider '{provider_name}' (ID: {provider_id}) connection test successful.")
    else:
        logger_instance.error(f"AD Provider '{provider_name}' (ID: {provider_id}) connection test failed.")
        # return False, provider_id # Decide if failed test means overall AD config step failed
    logger_instance.info(f"--- Finished AD Provider Configuration for '{provider_name}' ---")
    return test_success, provider_id # Success of the step depends on test_success


def handle_ntp_configuration(ome_client_instance: ome_client.OmeClient,
                             ntp_config_input: Optional[Dict], # Validated input payload
                             logger_instance: logging.Logger) -> bool:
    """Configures NTP servers in OME."""
    if not ntp_config_input:
        logger_instance.info("No NTP configuration data provided. Skipping NTP setup.")
        return True

    logger_instance.info("--- Configuring NTP Servers ---")
    # ntp_config_input is expected to be the direct payload for the API
    # after validation (e.g., containing EnableNTP, PrimaryNTPAddress, TimeZone)
    
    # Example validation check (should be in input_validator ideally)
    if ntp_config_input.get("EnableNTP") and not ntp_config_input.get("PrimaryNTPAddress"):
        logger_instance.error("Primary NTP server is required if EnableNTP is true. Skipping NTP config.")
        return False
    if ntp_config_input.get("EnableNTP") and not ntp_config_input.get("TimeZone"):
        logger_instance.error("TimeZone is required for NTP configuration if EnableNTP is true. Skipping NTP config.")
        return False

    logger_instance.info(f"Setting NTP configuration with payload: {ntp_config_input}")
    success = ome_client_instance.set_ntp_configuration(ntp_config_input) # type: ignore
    if success: logger_instance.info("NTP configuration updated successfully.")
    else: logger_instance.error("Failed to configure NTP.")
    logger_instance.info("--- Finished NTP Server Configuration ---")
    return success

def handle_dns_configuration(ome_client_instance: ome_client.OmeClient,
                             dns_servers_input: Optional[List[str]], # Validated list of DNS server IPs
                             logger_instance: logging.Logger,
                             max_wait_seconds: int = 300, poll_interval: int = 15) -> bool:
    """Configures DNS servers on the primary network adapter and monitors the job."""
    if not dns_servers_input:
        logger_instance.info("No DNS server list provided. Skipping DNS setup.")
        return True
    # Basic validation already done by collect_and_validate_list_inputs or get_single_input
    # More specific validation (IP format) would be in input_validator

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
                time.sleep(poll_interval)
                continue

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
        except Exception as e:
            logger_instance.error(f"Error retrieving status for DNS job {job_id}: {e}", exc_info=True)
        
        time.sleep(poll_interval)

    logger_instance.error(f"DNS configuration job {job_id} timed out after {max_wait_seconds} seconds.")
    return False

def handle_csr_generation(ome_client_instance: ome_client.OmeClient,
                          csr_details_input: Optional[Dict], # Validated input, keys match API payload
                          logger_instance: logging.Logger) -> bool:
    """Generates a CSR in OME."""
    if not csr_details_input:
        logger_instance.info("No CSR details provided. Skipping CSR generation.")
        return True

    logger_instance.info("--- Generating CSR (Certificate Signing Request) ---")
    # csr_details_input is expected to be the direct payload for the API after validation
    # and mapping of user-friendly keys (e.g. common_name) to API keys (e.g. DistinguishedName)
    # This mapping should happen in main() before calling this function.
    # For now, assume csr_details_input has the correct API keys.

    # Example of mapping if it were done here (better in main before validation):
    # payload = {
    #     "DistinguishedName": csr_details_input.get("common_name"), 
    #     "DepartmentName": csr_details_input.get("organizational_unit"), 
    #     # ... etc ...
    # }
    # payload_cleaned = {k: v for k, v in payload.items() if v is not None}
    # This function now expects csr_details_input to BE the cleaned payload.

    logger_instance.info(f"Requesting CSR generation with payload: {csr_details_input}")
    csr_pem = ome_client_instance.generate_csr(csr_details_input) # type: ignore
    
    if csr_pem:
        logger_instance.info("CSR generated successfully.")
        logger_instance.info("CSR (first 100 chars): " + csr_pem[:100].replace("\n", "\\n") + "...")
        logger_instance.debug(f"Full generated CSR:\n{csr_pem}")
        # Use a required field from the payload for the filename, e.g., DistinguishedName
        cn_for_filename = csr_details_input.get('DistinguishedName', 'ome_csr').replace('.', '_').replace('*','_wildcard_')
        csr_file_name = f"{cn_for_filename}.csr"
        try:
            with open(csr_file_name, 'w') as f: f.write(csr_pem)
            logger_instance.info(f"CSR saved to file: {csr_file_name}")
        except IOError as e: logger_instance.error(f"Failed to save CSR to file '{csr_file_name}': {e}")
        return True
    else:
        logger_instance.error("Failed to generate CSR.")
        return False

def handle_plugin_configuration(ome_client_instance: ome_client.OmeClient,
                                plugin_tasks_input: Optional[List[Dict]], # Validated list of plugin tasks
                                logger_instance: logging.Logger) -> bool:
    """Configures/Manages plugins in OME."""
    if not plugin_tasks_input:
        logger_instance.info("No plugin configuration tasks provided. Skipping plugin management.")
        return True

    logger_instance.info("--- Configuring/Managing Plugins ---")
    payload = {"Plugins": plugin_tasks_input} # plugin_tasks_input is the list of action dicts
    logger_instance.info(f"Submitting plugin actions with payload: {json.dumps(payload, indent=2)[:500]}...")
    
    success = ome_client_instance.update_console_plugins(payload) # type: ignore
    if success: logger_instance.info("Plugin actions request submitted successfully.")
    else: logger_instance.error("Failed to submit plugin actions request.")
    logger_instance.info("--- Finished Plugin Management ---")
    return success

def handle_static_group_creation(ome_client_instance: ome_client.OmeClient,
                                 static_group_tasks_input: Optional[List[Dict]], # Validated list of group tasks
                                 logger_instance: logging.Logger) -> bool:
    """Creates static groups in OME. Uses the comprehensive static group definition."""
    if not static_group_tasks_input:
        logger_instance.info("No static group creation tasks provided. Skipping static group creation.")
        return True
        
    logger_instance.info("--- Creating Static Groups (using comprehensive definition) ---")
    overall_success = True
    for task in static_group_tasks_input:
        # Task structure from input_validator for STATIC_GROUP_CLI_ARG_NAME:
        # {'group_name', devices', 'parent_group', 'create', 'identifier_type'}
        group_name = task.get("group_name") # Required, checked by validator
        description = task.get("description") # Not in original STATIC_GROUP_OPTIONAL_KEYS, add if needed
        create_flag = task.get("create", constants.DEFAULT_CREATE_FLAG) # Should this be True for initial setup?
        parent_group_name = task.get("parent_group", constants.DEFAULT_PARENT_GROUP)
        # Devices and identifier_type are for adding members, initial setup might just create empty.

        if not group_name: # Should be caught by validator
            logger_instance.error(f"Invalid static group task: {task}. 'group_name' is missing.")
            overall_success = False
            continue

        existing_group = ome_client_instance.get_group_by_name(group_name) # type: ignore
        if existing_group and existing_group.get("Id"):
            logger_instance.warning(f"Static group '{group_name}' already exists with ID {existing_group.get('Id')}. Skipping creation.")
            # If devices are specified, could proceed to add members to existing group.
            # For now, just skipping creation.
            continue
        
        if not create_flag: # If create is explicitly false and group doesn't exist
            logger_instance.info(f"Static group '{group_name}' does not exist and 'create' flag is false. Skipping.")
            continue

        parent_id: Optional[int] = None
        if parent_group_name:
            parent_group_obj = ome_client_instance.get_group_by_name(parent_group_name)
            if parent_group_obj and parent_group_obj.get('Id'):
                try: parent_id = int(parent_group_obj['Id'])
                except (ValueError, TypeError):
                    logger_instance.error(f"Parent group '{parent_group_name}' has invalid ID '{parent_group_obj.get('Id')}'. Cannot create '{group_name}'.")
                    overall_success = False; continue
            else:
                logger_instance.error(f"Parent group '{parent_group_name}' not found. Cannot create '{group_name}'.")
                overall_success = False; continue
        
        logger_instance.info(f"Creating static group: '{group_name}' (Description: '{description or group_name}')" + (f" under parent ID {parent_id}" if parent_id else ""))
        # ome_client.create_static_group takes name, description, parent_id (int)
        group_id_str = ome_client_instance.create_static_group(group_name, description, parent_id) # type: ignore
        
        if group_id_str:
            logger_instance.info(f"Static group '{group_name}' created successfully with ID: {group_id_str}.")
            # TODO: If task['devices'] are present, resolve and add them here using logic similar to sg_group.py
            # For initial setup, this might be out of scope if only empty groups are intended.
        else:
            logger_instance.error(f"Failed to create static group '{group_name}'.")
            overall_success = False
    logger_instance.info("--- Finished Static Group Creation ---")
    return overall_success

# --- AD Group Import Functions ---
def run_ad_import_workflow(ome_client_instance: ome_client.OmeClient, ad_provider_id: int,
                           ad_provider_name_for_logging: str, ad_search_username: str, ad_search_password: str,
                           normalized_ad_import_tasks: List[Dict], logger_instance: logging.Logger) -> bool:
    logger_instance.info(f"Starting AD group import workflow for {len(normalized_ad_import_tasks)} task(s) via provider '{ad_provider_name_for_logging}' (ID: {ad_provider_id}).")
    if not normalized_ad_import_tasks: return True
    overall_success = True
    for task in normalized_ad_import_tasks:
        if not process_ad_import_task(ome_client_instance, ad_provider_id, ad_search_username, ad_search_password, task, logger_instance):
            overall_success = False 
    return overall_success

def process_ad_import_task(ome_client_instance: ome_client.OmeClient, ad_provider_id: int,
                           ad_search_username: str, ad_search_password: str,
                           import_task: Dict, logger_instance: logging.Logger) -> bool:
    ad_group_name = import_task.get('group_name')
    role_name = import_task.get('role_name', constants.DEFAULT_AD_IMPORT_ROLE)
    raw_scope_input = import_task.get('scope_name') 
    logger_instance.info(f"--- Processing AD group import: '{ad_group_name}' ---")
    ad_object_guid: Optional[str] = None
    ome_role_id: Optional[str] = None
    imported_ome_account_id_str: Optional[str] = None
    try:
        logger_instance.debug(f"Searching for AD group '{ad_group_name}' via Provider ID {ad_provider_id}...")
        ad_group_details = ome_client_instance.search_ad_group_in_ome_by_name(
            ad_provider_id, ad_group_name, ad_search_username, ad_search_password
        )
        if ad_group_details and ad_group_details.get('ObjectGuid'):
            ad_object_guid = str(ad_group_details['ObjectGuid'])
            logger_instance.info(f"Found AD group '{ad_group_name}' with ObjectGuid: {ad_object_guid}")
        else:
            logger_instance.error(f"AD group '{ad_group_name}' not found or ObjectGuid missing. Task failed.")
            return False

        logger_instance.debug(f"Finding OME Role ID for role name '{role_name}'...")
        ome_role_id_raw = ome_client_instance.get_role_id_by_name(role_name)
        if ome_role_id_raw:
            ome_role_id = str(ome_role_id_raw)
            logger_instance.info(f"Found OME Role ID for '{role_name}': {ome_role_id}")
        else:
            logger_instance.error(f"OME Role '{role_name}' not found. Task failed for AD group '{ad_group_name}'.")
            return False

        logger_instance.info(f"Checking if OME Account with UserName '{ad_group_name}' already exists...")
        existing_ome_account = ome_client_instance.get_imported_ad_account_by_username(ad_group_name)
        if existing_ome_account:
            existing_ome_account_id_raw = existing_ome_account.get('Id')
            if existing_ome_account_id_raw is not None:
                imported_ome_account_id_str = str(existing_ome_account_id_raw)
                logger_instance.warning(f"OME Account '{ad_group_name}' already exists (ID: {imported_ome_account_id_str}). Skipping import, proceeding to scope.")
            else:
                logger_instance.warning(f"OME Account '{ad_group_name}' found but ID missing. Attempting fresh import.")
        else:
            logger_instance.info(f"OME Account '{ad_group_name}' not found. Proceeding with import.")

        if not imported_ome_account_id_str:
            logger_instance.info(f"Attempting to import AD group '{ad_group_name}'...")
            import_result_id = ome_client_instance.import_ad_group(ad_provider_id, ad_group_name, ad_object_guid, ome_role_id) # type: ignore
            if import_result_id:
                imported_ome_account_id_str = str(import_result_id)
                logger_instance.info(f"AD group '{ad_group_name}' imported. New OME Account ID: {imported_ome_account_id_str}")
            else:
                logger_instance.error(f"AD group import for '{ad_group_name}' failed. Task failed.")
                return False
        
        individual_scope_names: List[str] = []
        if isinstance(raw_scope_input, list):
            for item in raw_scope_input:
                if isinstance(item, str) and item.strip(): individual_scope_names.append(item.strip())
        elif isinstance(raw_scope_input, str) and raw_scope_input.strip():
            if ',' in raw_scope_input: individual_scope_names.extend([s.strip() for s in raw_scope_input.split(',') if s.strip()])
            else: individual_scope_names.append(raw_scope_input.strip())

        if imported_ome_account_id_str and raw_scope_input is not None:
            scope_group_ids_str: List[str] = []
            if individual_scope_names:
                for s_name in individual_scope_names:
                    details = ome_client_instance.get_group_by_name(s_name)
                    if details and details.get('Id'): scope_group_ids_str.append(str(details['Id']))
                    else: logger_instance.warning(f"Scope group '{s_name}' not found for AD group '{ad_group_name}'.")
            
            logger_instance.info(f"Setting scopes for account '{imported_ome_account_id_str}' to groups: {scope_group_ids_str}")
            ome_client_instance.add_scope_to_ad_group(imported_ome_account_id_str, scope_group_ids_str)
        elif imported_ome_account_id_str and raw_scope_input is None:
             logger_instance.info(f"No 'scope_name' for AD group '{ad_group_name}'. Existing scopes unchanged.")
        
        logger_instance.info(f"--- Successfully processed AD group import for '{ad_group_name}' ---")
        return True
    except Exception as e:
        logger_instance.error(f"Unexpected error processing AD import task for '{ad_group_name}': {e}", exc_info=True)
        return False

#------------------------------------------------------------------------------
# Main execution block
#------------------------------------------------------------------------------
def main():
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
    grp_ad_provider.add_argument(f'--{constants.AD_PROVIDER_FIND_CLI_MAP.get("ad_provider_name", "ad-provider-name")}', dest='ad_provider_name', metavar='NAME', help="Name for AD provider in OME.") # Uses key from map
    grp_ad_provider.add_argument(f'--{constants.AD_PROVIDER_CONFIGURE_PARAMETER_CLI_ARG_NAME.replace("_", "-")}', dest='ad_configure_parameter_cli', metavar='JSON_STRING', help="JSON for full AD provider config (payload).")
    grp_ad_provider.add_argument(f'--{constants.AD_CRED_CLI_MAP.get("ad_search_username", "ad-search-username")}', dest='ad_search_username', metavar='USER', help="AD username for OME to search AD.")
    grp_ad_provider.add_argument(f'--{constants.AD_CRED_CLI_MAP.get("ad_search_password", "ad-search-password")}', dest='ad_search_password', metavar='PASS', help="AD password for OME to search AD.")

    grp_ntp = parser.add_argument_group('NTP Configuration Details')
    grp_ntp.add_argument(f'--{constants.NTP_PAYLOAD_CLI_ARG_NAME.replace("_", "-")}', dest='ntp_payload_cli', metavar='JSON_STRING', help="JSON for NTP config (e.g., '{\"primary_server\": \"s1\"...}').")

    grp_dns = parser.add_argument_group('DNS Configuration Details')
    grp_dns.add_argument(f'--{constants.DNS_SERVERS_CLI_ARG_NAME.replace("_", "-")}', dest='dns_servers_cli', metavar='"S1,S2"', help="Comma-separated list of DNS server IPs.")

    grp_csr = parser.add_argument_group('CSR Generation Details')
    grp_csr.add_argument(f'--{constants.CSR_DETAILS_PAYLOAD_CLI_ARG_NAME.replace("_", "-")}', dest='csr_payload_cli', metavar='JSON_STRING', help="JSON for CSR details (payload for GenerateCSR action).")

    grp_plugins = parser.add_argument_group('Plugin Configuration Tasks')
    grp_plugins.add_argument(f'--{constants.PLUGIN_ACTION_TASK_CLI_ARG_NAME.replace("_", "-")}', dest='plugin_action_tasks_cli', action='append', metavar='JSON_STRING', help="JSON for one plugin task ('{\"Id\":\"GUID\"...}'). Multi-use.")

    grp_static_groups = parser.add_argument_group('Static Group Creation Tasks')
    # Uses STATIC_GROUP_CLI_ARG_NAME from constants (value 'StaticGroup')
    grp_static_groups.add_argument(f'--{constants.STATIC_GROUP_CLI_ARG_NAME}', dest='static_group_tasks_cli', action='append', metavar='JSON_STRING', help="JSON for one static group ('{\"group_name\":\"N\"...}'). Multi-use.")
    
    grp_ad_import = parser.add_argument_group('AD Group Import Tasks')
    # Uses AD_IMPORT_GROUP_CLI_ARG_NAME from constants (value 'adgroup')
    ad_import_help = (f"JSON for AD import task (keys: group_name, role_name, Scope). Default role: {constants.DEFAULT_AD_IMPORT_ROLE}. Multi-use.")
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
        ome_client_instance = ome_client.OmeClient(ome_creds['url'], ome_creds['username'], ome_creds['password']) # Removed logger_instance
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
    ad_provider_id_from_config_step: Optional[int] = None # Store ID if AD is configured in this run

    # --- 1. AD Configuration ---
    if run_all or args.run_ad_config:
        logger.info("--- Preparing for AD Provider Configuration ---")
        # Full AD Provider payload from CLI or 'ActiveDirectory' section in config
        ad_provider_payload = utils.get_single_input(
            args.ad_configure_parameter_cli, # From --ad-configure-parameter
            config, 
            constants.AD_CONFIG_SECTION, # 'ActiveDirectory'
            logger,
            is_json_string_cli=True # Assume CLI arg is JSON string
        )
        # AD Search credentials for TestADConnection (also from 'ActiveDirectory' or specific CLI)
        ad_search_creds_input = utils.collect_and_validate_credentials(
            args, config, constants.AD_CRED_REQUIRED_KEYS, constants.AD_CONFIG_SECTION,
            constants.AD_CRED_CLI_MAP, input_validator.validate_ad_search_credentials_specific_min, logger # Min validator for just creds
        )[0] # Get just the dict

        if ad_provider_payload:
            # TODO: Validate ad_provider_payload using input_validator.validate_ad_provider_payload_specific
            # This validator should use constants.AD_PROVIDER_PAYLOAD_REQUIRED_KEYS
            # For now, ensure 'Name' is present for logging and basic function
            if 'Name' not in ad_provider_payload and args.ad_provider_name:
                ad_provider_payload['Name'] = args.ad_provider_name
            
            if not ad_provider_payload.get('Name'):
                logger.error("AD Provider 'Name' missing for configuration. Skipping AD setup.")
                overall_script_success = False
            elif not ad_search_creds_input.get('Username') or not ad_search_creds_input.get('Password'):
                logger.error("AD Search Username/Password missing for TestADConnection. Skipping AD setup.")
                overall_script_success = False
            else:
                success, prov_id = handle_ad_configuration(ome_client_instance, ad_provider_payload, ad_search_creds_input, logger)
                if not success: overall_script_success = False
                if prov_id is not None: ad_provider_id_from_config_step = prov_id
        elif run_all or args.run_ad_config:
             logger.warning("AD configuration requested but no payload data found. Skipping.")

    # --- 2. NTP Configuration ---
    if run_all or args.run_ntp_config:
        logger.info("--- Preparing for NTP Configuration ---")
        ntp_payload = utils.get_single_input(args.ntp_payload_cli, config, constants.NTP_CONFIG_SECTION, logger, is_json_string_cli=True)
        if ntp_payload:
            # TODO: Validate ntp_payload using input_validator.validate_ntp_payload_specific
            if not handle_ntp_configuration(ome_client_instance, ntp_payload, logger):
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
        if not isinstance(dns_servers_list_file, list): dns_servers_list_file = [] # Ensure it's a list

        dns_servers_to_use = dns_servers_list_cli if dns_servers_list_cli else dns_servers_list_file
        
        if dns_servers_to_use:
            # TODO: Validate dns_servers_to_use (e.g., IP format, count using DNS_SERVERS_LIST_MIN_MAX)
            if not handle_dns_configuration(ome_client_instance, dns_servers_to_use, logger):
                overall_script_success = False
        elif run_all or args.run_dns_config:
            logger.warning("DNS configuration requested but no DNS servers provided. Skipping.")

    # --- 4. CSR Generation ---
    if run_all or args.run_csr_generation:
        logger.info("--- Preparing for CSR Generation ---")
        csr_payload = utils.get_single_input(args.csr_payload_cli, config, constants.CSR_CONFIG_SECTION, logger, is_json_string_cli=True)
        if csr_payload:
            # TODO: Validate csr_payload using input_validator.validate_csr_payload_specific
            # The handle_csr_generation function currently does internal mapping from common names to API keys.
            # Consider if validation should happen on common names or API keys.
            if not handle_csr_generation(ome_client_instance, csr_payload, logger): # csr_payload here should have API keys
                overall_script_success = False
        elif run_all or args.run_csr_generation:
            logger.warning("CSR generation requested but no payload data found. Skipping.")

    # --- 5. Plugin Configuration ---
    if run_all or args.run_plugin_config:
        logger.info("--- Preparing for Plugin Configuration ---")
        valid_tasks, invalid_details = utils.collect_and_validate_list_inputs(
            args, config, constants.PLUGIN_ACTION_TASK_CLI_ARG_NAME, constants.PLUGIN_TASKS_CONFIG_SECTION,
            input_validator.validate_plugin_action_task_specific, logger # TODO: Implement this validator
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
        # Using original constants for comprehensive static group definition
        valid_tasks, invalid_details = utils.collect_and_validate_list_inputs(
            args, config, constants.STATIC_GROUP_CLI_ARG_NAME, constants.STATIC_GROUP_CONFIG_SECTION,
            input_validator.validate_static_group_definition_specific, logger # Existing validator
        )
        if invalid_details:
            logger.warning(f"Skipping {len(invalid_details)} invalid static group creation tasks.")
            for item, errs, src in invalid_details: logger.error(f"  Invalid static group task from {src}: {item} -> {errs}")
        if valid_tasks:
            if not handle_static_group_creation(ome_client_instance, valid_tasks, logger):
                overall_script_success = False
        elif run_all or args.run_static_group_creation:
            logger.info("Static group creation requested but no valid tasks found. Skipping.")
            
    # --- 7. AD Group Import ---
    if run_all or args.run_ad_group_import:
        logger.info("--- Preparing for AD Group Import ---")
        # Determine AD provider ID: use one from AD config step, or find by name from CLI/config
        ad_provider_id_for_import_final = ad_provider_id_from_config_step
        ad_provider_name_for_import_final = args.ad_provider_name # From --ad-provider-name
        
        if ad_provider_id_for_import_final is None and ad_provider_name_for_import_final:
            logger.info(f"AD Provider ID not set from AD config step. Finding by name '{ad_provider_name_for_import_final}' for import...")
            try:
                pid_raw = ome_client_instance.get_ad_provider_id_by_name(ad_provider_name_for_import_final)
                if pid_raw is not None: ad_provider_id_for_import_final = int(pid_raw)
                else: logger.error(f"AD Provider '{ad_provider_name_for_import_final}' not found for import.")
            except Exception as e: logger.error(f"Error finding AD Provider '{ad_provider_name_for_import_final}': {e}")
        
        # Get AD search credentials (may have been fetched earlier for AD config test)
        ad_search_creds_for_import = utils.collect_and_validate_credentials(
            args, config, constants.AD_CRED_REQUIRED_KEYS, constants.AD_CONFIG_SECTION,
            constants.AD_CRED_CLI_MAP, input_validator.validate_ad_search_credentials_specific_min, logger 
        )[0]

        if ad_provider_id_for_import_final is not None and \
           ad_search_creds_for_import.get('Username') and ad_search_creds_for_import.get('Password'):
            
            valid_ad_import_tasks, invalid_ad_tasks = utils.collect_and_validate_list_inputs(
                args, config, constants.AD_IMPORT_GROUP_CLI_ARG_NAME, 
                constants.AD_IMPORT_GROUP_CONFIG_SECTION, input_validator.validate_ad_import_task_specific, logger
            )
            if invalid_ad_tasks: 
                logger.warning(f"Skipping {len(invalid_ad_tasks)} invalid AD import tasks.")
                for item, errs, src in invalid_ad_tasks: logger.error(f"  Invalid AD import task from {src}: {item} -> {errs}")

            if valid_ad_import_tasks:
                normalized_tasks = []
                for task in valid_ad_import_tasks:
                    normalized_tasks.append({
                        "group_name": task["group_name"],
                        "role_name": task.get("role_name", constants.DEFAULT_AD_IMPORT_ROLE),
                        "scope_name": task.get("Scope", task.get("scope_name")) # Prefer 'Scope' if present, else 'scope_name'
                    })
                if not run_ad_import_workflow(
                    ome_client_instance, ad_provider_id_for_import_final,
                    ad_provider_name_for_import_final or f"ID_{ad_provider_id_for_import_final}",
                    ad_search_creds_for_import['Username'], ad_search_creds_for_import['Password'],
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
