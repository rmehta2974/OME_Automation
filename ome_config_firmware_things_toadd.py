def resolve_target_device_ids(
    ome_client_instance: ome_client.OmeClient,
    target_group_names: Optional[List[str]] = None,
    target_device_ids_direct: Optional[List[Union[int,str]]] = None, 
    target_service_tags: Optional[List[str]] = None,
    target_idrac_ips: Optional[List[str]] = None,
    target_device_names: Optional[List[str]] = None,
    logger_instance: logging.Logger
) -> List[int]:
    """
    Resolves various target specifications to a unique list of OME Device IDs.
    Adapts logic from update_firmware_using_catalog.py's get_device_id and group resolution.
    """
    all_device_ids = set()
    logger_instance.debug("Starting target device ID resolution...")

    # 1. From direct Device IDs
    if target_device_ids_direct:
        for dev_id_input in target_device_ids_direct:
            try: 
                all_device_ids.add(int(dev_id_input))
                logger_instance.debug(f"Added direct device ID: {dev_id_input}")
            except ValueError: 
                logger_instance.warning(f"Invalid direct device ID '{dev_id_input}' (not an integer), skipping.")

    # 2. From Group Names
    if target_group_names:
        for group_name in target_group_names:
            group_details = ome_client_instance.get_group_by_name(group_name) # type: ignore
            if group_details and group_details.get('Id'):
                group_id = int(group_details['Id'])
                logger_instance.info(f"Fetching devices for group '{group_name}' (ID: {group_id})...")
                devices_in_group = ome_client_instance.get_devices_by_group_id(group_id) # type: ignore
                if devices_in_group:
                    for dev in devices_in_group:
                        if dev.get('Id') is not None: all_device_ids.add(int(dev['Id']))
                    logger_instance.info(f"Added {len(devices_in_group)} devices from group '{group_name}'.")
                else:
                    logger_instance.warning(f"No devices found in group '{group_name}' or failed to retrieve.")
            else:
                logger_instance.warning(f"Group '{group_name}' not found. Cannot get devices.")
    
    # 3. From Service Tags, Device Names, iDRAC IPs (requires individual lookups or smart filtering)
    # Adapting the single lookup logic from update_firmware_using_catalog.py's get_device_id
    
    identifiers_to_lookup: List[Tuple[str, str, str]] = [] # (type_for_log, filter_key, value)
    if target_service_tags:
        identifiers_to_lookup.extend([("ServiceTag", "DeviceServiceTag", tag) for tag in target_service_tags])
    if target_device_names:
        identifiers_to_lookup.extend([("DeviceName", "DeviceName", name) for name in target_device_names])
    if target_idrac_ips: # This is the most complex to filter directly via OData usually
        identifiers_to_lookup.extend([("iDRAC IP", "DeviceManagement/any(d:d/NetworkAddress eq '{value}')", ip) for ip in target_idrac_ips])

    for id_type_log, filter_key_template, id_val in identifiers_to_lookup:
        # Construct filter: ensure proper quoting for string values in OData
        escaped_id_val = id_val.replace("'", "''")
        if "{value}" in filter_key_template: # For complex filters like iDRAC IP
             filter_str = filter_key_template.format(value=escaped_id_val)
        else: # For simple equality like Name eq 'value'
             filter_str = f"{filter_key_template} eq '{escaped_id_val}'"
        
        logger_instance.debug(f"Looking up device by {id_type_log}: '{id_val}' using filter: {filter_str}")
        devices = ome_client_instance.get_devices_by_filter(filter_str) # type: ignore
        if devices:
            if len(devices) > 1:
                logger_instance.warning(f"Found multiple devices for {id_type_log} '{id_val}'. Using first one: ID {devices[0].get('Id')}")
            dev_id_found = devices[0].get('Id')
            if dev_id_found is not None:
                all_device_ids.add(int(dev_id_found))
                logger_instance.info(f"Resolved {id_type_log} '{id_val}' to Device ID: {dev_id_found}")
            else:
                 logger_instance.warning(f"Device found for {id_type_log} '{id_val}' but it has no ID.")
        else:
            logger_instance.warning(f"No device found for {id_type_log} = '{id_val}'.")
                
    resolved_list = sorted(list(all_device_ids))
    logger_instance.info(f"Resolved a total of {len(resolved_list)} unique target device IDs for operation.")
    logger_instance.debug(f"Final resolved Device IDs: {resolved_list}")
    return resolved_list


#------------------------------------------------------------------------------
# Configuration Task Functions (Adapted & New)
#------------------------------------------------------------------------------

def handle_catalog_management(ome_client_instance: ome_client.OmeClient,
                              catalog_task_input: Optional[Dict], 
                              catalog_name_to_find: Optional[str], 
                              refresh_flag: bool,
                              logger_instance: logging.Logger) -> Tuple[bool, Optional[int], Optional[int]]:
    """Manages catalogs. Returns (success, catalog_id, repository_id)."""
    logger_instance.info("--- Managing Catalog ---")
    if catalog_name_to_find: 
        logger_instance.info(f"Looking for existing catalog: '{catalog_name_to_find}'")
        catalogs = ome_client_instance.get_catalogs(catalog_name=catalog_name_to_find) # type: ignore
        if catalogs is None: logger_instance.error(f"Failed to get details for catalog '{catalog_name_to_find}'."); return False, None, None
        found_catalog = None
        if catalogs:
            for cat in catalogs:
                if cat.get("Name") == catalog_name_to_find or (cat.get("Repository") and cat["Repository"].get("Name") == catalog_name_to_find):
                    found_catalog = cat; break
            if not found_catalog and catalogs: found_catalog = catalogs[0] 
        if found_catalog and found_catalog.get("Id") is not None and found_catalog.get("Repository") and found_catalog["Repository"].get("Id") is not None:
            cat_id, repo_id = int(found_catalog["Id"]), int(found_catalog["Repository"]["Id"])
            logger_instance.info(f"Found catalog '{found_catalog.get('Name', catalog_name_to_find)}' (ID: {cat_id}, RepoID: {repo_id}).")
            if refresh_flag:
                logger_instance.info(f"Refresh requested for catalog ID {cat_id}.")
                refresh_task = ome_client_instance.refresh_catalog(cat_id) # type: ignore
                if refresh_task and refresh_task.get("TaskId"):
                    if not track_ome_job_completion(ome_client_instance, refresh_task["TaskId"], f"Catalog Refresh ID {cat_id}", logger_instance):
                        logger_instance.error(f"Catalog refresh job for ID {cat_id} failed/timed out."); return False, cat_id, repo_id
                    logger_instance.info(f"Catalog ID {cat_id} refreshed.")
                elif refresh_task and refresh_task.get("status") == "accepted_no_content":
                     logger_instance.info(f"Catalog refresh for ID {cat_id} accepted (204).")
                else: logger_instance.error(f"Failed to initiate refresh for catalog ID {cat_id}."); return False, cat_id, repo_id
            return True, cat_id, repo_id
        else: logger_instance.error(f"Catalog '{catalog_name_to_find}' not found or incomplete."); return False, None, None
    elif catalog_task_input: 
        repo_type = catalog_task_input.get('repo_type','').upper()
        repo_source_ip = catalog_task_input.get('repo_source_ip')
        catalog_path_input = catalog_task_input.get('catalog_path')
        repo_user, repo_pass = catalog_task_input.get('repo_user'), catalog_task_input.get('repo_password')
        repo_domain = catalog_task_input.get('repo_domain')
        cat_name_prefix = catalog_task_input.get('catalog_name_prefix', 'ScriptedDellOnline')
        
        source_path, filename, source, gen_repo_name = "", "", "", ""
        if repo_type == 'DELL_ONLINE':
            source = "downloads.dell.com"; filename = "catalog.xml" # Default, API might ignore filename for DELL_ONLINE
            gen_repo_name = f"{cat_name_prefix}_{time.strftime('%Y%m%d%H%M%S')}"
        elif repo_type == 'LOCAL':
            source = catalog_path_input # For LOCAL, source is the full path
            path_tuple = os.path.split(catalog_path_input)
            source_path = path_tuple[0] # This might be empty if path is just filename
            filename = path_tuple[1]
            gen_repo_name = f"LOCAL_{filename.split('.')[0]}_{time.strftime('%Y%m%d%H%M%S')}"
        elif repo_type in ['NFS', 'CIFS', 'HTTP', 'HTTPS']:
            if not repo_source_ip or not catalog_path_input: logger_instance.error(f"IP/Path required for '{repo_type}'."); return False, None, None
            source = repo_source_ip; path_tuple = os.path.split(catalog_path_input)
            source_path = path_tuple[0]; filename = path_tuple[1]   
            gen_repo_name = f"{repo_type}_{repo_source_ip.replace('.', '_')}_{filename.split('.')[0]}_{time.strftime('%Y%m%d%H%M%S')}"
        else: logger_instance.error(f"Unsupported repo_type '{repo_type}' for catalog creation."); return False, None, None

        api_payload = {
            "Filename": filename, "SourcePath": source_path,
            "Repository": {
                "Name": gen_repo_name, "Description": "Catalog by OME Config Manager",
                "RepositoryType": repo_type, "Source": source,
                "DomainName": repo_domain or "", "Username": repo_user or "", "Password": repo_pass or "",
                "CheckCertificate": catalog_task_input.get("check_certificate", False)
            }}
        logger_instance.info(f"Creating new catalog: '{gen_repo_name}'")
        logger_instance.debug(f"Catalog creation payload: {api_payload}")
        created_info = ome_client_instance.create_catalog(api_payload) # type: ignore
        if created_info and created_info.get("TaskId") and created_info.get("Id") is not None and \
           created_info.get("Repository") and created_info["Repository"].get("Id") is not None:
            cid, rid, tid = int(created_info["Id"]), int(created_info["Repository"]["Id"]), created_info["TaskId"]
            logger_instance.info(f"Catalog creation task submitted. TaskID: {tid}. New CatalogID: {cid}, RepoID: {rid}.")
            if not track_ome_job_completion(ome_client_instance, tid, f"New Catalog '{gen_repo_name}'", logger_instance):
                logger_instance.error(f"Catalog creation job for '{gen_repo_name}' failed/timed out."); return False, cid, rid
            logger_instance.info(f"Catalog '{gen_repo_name}' created and processed."); return True, cid, rid
        else: logger_instance.error(f"Catalog creation failed. Response: {created_info}"); return False, None, None
    else: logger_instance.info("No catalog operation requested."); return True, None, None

def handle_baseline_management(ome_client_instance: ome_client.OmeClient,
                               baseline_task_input: Optional[Dict], 
                               baseline_name_to_find: Optional[str],
                               catalog_id_from_prev_step: Optional[int], 
                               repo_id_from_prev_step: Optional[int],    
                               logger_instance: logging.Logger) -> Tuple[bool, Optional[int], Optional[int]]:
    logger_instance.info("--- Managing Baseline ---")
    if baseline_name_to_find:
        logger_instance.info(f"Looking for existing baseline: '{baseline_name_to_find}'")
        baselines = ome_client_instance.get_baselines(baseline_name=baseline_name_to_find) # type: ignore
        if baselines is None: logger_instance.error(f"Failed to get details for baseline '{baseline_name_to_find}'."); return False, None, None
        if baselines:
            b_data = baselines[0]; b_id = int(b_data["Id"])
            # TaskId from creation is the compliance job. If just getting existing, might not have it readily.
            comp_job_id = b_data.get("TaskId", b_data.get("ComplianceJobId")) 
            logger_instance.info(f"Found baseline '{b_data.get('Name')}' (ID: {b_id}). ComplianceJobId (if known): {comp_job_id}")
            return True, b_id, int(comp_job_id) if comp_job_id else None
        else: logger_instance.error(f"Baseline '{baseline_name_to_find}' not found."); return False, None, None
    elif baseline_task_input:
        b_name = baseline_task_input.get('baseline_name')
        cat_ref = baseline_task_input.get('catalog_name_or_id')
        logger_instance.info(f"Creating new baseline '{b_name}' using catalog '{cat_ref}'.")
        cur_cat_id, cur_repo_id = catalog_id_from_prev_step, repo_id_from_prev_step
        if not cur_cat_id:
            if isinstance(cat_ref, str):
                cats = ome_client_instance.get_catalogs(catalog_name=cat_ref) # type: ignore
                if cats and cats[0].get("Id") is not None and cats[0].get("Repository", {}).get("Id") is not None:
                    cur_cat_id, cur_repo_id = int(cats[0]["Id"]), int(cats[0]["Repository"]["Id"])
                    logger_instance.info(f"Found catalog '{cat_ref}' ID: {cur_cat_id}, RepoID: {cur_repo_id}")
                else: logger_instance.error(f"Could not find catalog '{cat_ref}'."); return False, None, None
            elif isinstance(cat_ref, int): cur_cat_id = cat_ref # Assume repo_id also provided or fetched
            else: logger_instance.error(f"Invalid 'catalog_name_or_id': {cat_ref}."); return False, None, None
        if not cur_cat_id or not cur_repo_id: # Try to fetch repo_id if only cat_id known
            if cur_cat_id and not cur_repo_id:
                cat_details_list = ome_client_instance.get_catalogs(catalog_id_filter=cur_cat_id) # type: ignore
                if cat_details_list and cat_details_list[0].get("Repository",{}).get("Id"):
                    cur_repo_id = int(cat_details_list[0]["Repository"]["Id"])
            if not cur_cat_id or not cur_repo_id:
                 logger_instance.error("CatalogID or RepoID undetermined for baseline."); return False, None, None
        
        target_dev_ids = resolve_target_device_ids(
            ome_client_instance, baseline_task_input.get('target_group_names'),
            baseline_task_input.get('target_device_ids'), baseline_task_input.get('target_service_tags'),
            baseline_task_input.get('target_idrac_ips'), baseline_task_input.get('target_device_names'), logger_instance
        )
        
        device_type_map = {int(dt['DeviceType']): dt['Name'] for dt in ome_client_instance.get_device_type_details() or [] if dt.get("DeviceType") is not None} # type: ignore
        targets_payload = []
        if target_dev_ids:
            dev_details_list = ome_client_instance.get_devices_by_ids(target_dev_ids) # type: ignore
            if dev_details_list:
                for dev in dev_details_list:
                    dev_id, dev_type_id_int = dev.get("Id"), dev.get("Type")
                    if dev_id is not None and dev_type_id_int is not None:
                        targets_payload.append({"Id": dev_id, "Type": {"Id": dev_type_id_int, "Name": device_type_map.get(dev_type_id_int, "Unknown")}})
        
        b_payload = {
            'Name': b_name, 'Description': baseline_task_input.get('description', f"Baseline {b_name}"),
            'CatalogId': cur_cat_id, 'RepositoryId': cur_repo_id,
            'DowngradeEnabled': baseline_task_input.get('downgrade_enabled', True),
            'Is64Bit': baseline_task_input.get('is_64bit', True), 'Targets': targets_payload
        }
        logger_instance.debug(f"Baseline creation payload: {b_payload}")
        created_b_info = ome_client_instance.create_baseline(b_payload) # type: ignore
        if created_b_info and created_b_info.get("Id") is not None and created_b_info.get("TaskId") is not None:
            b_id, c_job_id = int(created_b_info["Id"]), int(created_b_info["TaskId"])
            logger_instance.info(f"Baseline '{b_name}' task submitted. ID: {b_id}, ComplianceJobID: {c_job_id}.")
            if not track_ome_job_completion(ome_client_instance, c_job_id, f"Baseline Creation/Compliance '{b_name}'", logger_instance):
                logger_instance.error(f"Baseline job for '{b_name}' failed/timed out."); return False, b_id, c_job_id
            logger_instance.info(f"Baseline '{b_name}' created & initial compliance done."); return True, b_id, c_job_id
        else: logger_instance.error(f"Baseline creation for '{b_name}' failed. Response: {created_b_info}"); return False, None, None
    else: logger_instance.info("No baseline operation requested."); return True, None, None

def handle_firmware_update(ome_client_instance: ome_client.OmeClient,
                           firmware_task_input: Optional[Dict], 
                           baseline_id_from_prev_step: Optional[int],
                           catalog_id_from_prev_step: Optional[int], 
                           repo_id_from_prev_step: Optional[int],    
                           initial_compliance_job_id: Optional[int], 
                           logger_instance: logging.Logger) -> bool:
    if not firmware_task_input: logger_instance.info("No firmware update task input. Skipping."); return True
    logger_instance.info("--- Managing Firmware Update ---")
    baseline_ref = firmware_task_input.get('baseline_name_or_id')
    cur_baseline_id, cur_catalog_id, cur_repo_id, cur_comp_job_id = \
        baseline_id_from_prev_step, catalog_id_from_prev_step, repo_id_from_prev_step, initial_compliance_job_id

    if not cur_baseline_id:
        if isinstance(baseline_ref, str):
            logger_instance.info(f"Baseline ID not from prev step, finding by name: {baseline_ref}")
            baselines = ome_client_instance.get_baselines(baseline_name=baseline_ref) # type: ignore
            if baselines and baselines[0].get("Id") is not None:
                b_data = baselines[0]; cur_baseline_id = int(b_data["Id"])
                if cur_catalog_id is None and b_data.get("CatalogId"): cur_catalog_id = int(b_data["CatalogId"])
                if cur_repo_id is None and b_data.get("RepositoryId"): cur_repo_id = int(b_data["RepositoryId"])
                # Original compliance job ID might not be easily found for an existing baseline.
                logger_instance.info(f"Found baseline '{baseline_ref}' ID: {cur_baseline_id}. CatalogID: {cur_catalog_id}, RepoID: {cur_repo_id}")
            else: logger_instance.error(f"Could not find baseline '{baseline_ref}'."); return False
        elif isinstance(baseline_ref, int): cur_baseline_id = baseline_ref
        else: logger_instance.error(f"Invalid 'baseline_name_or_id': {baseline_ref}."); return False
    
    if not all([cur_baseline_id, cur_catalog_id, cur_repo_id]): # Try to fetch missing catalog/repo IDs if only baseline ID is known
        if cur_baseline_id and (cur_catalog_id is None or cur_repo_id is None):
            bl_details_list = ome_client_instance.get_baselines(baseline_id_filter=cur_baseline_id) # type: ignore
            if bl_details_list and bl_details_list[0]:
                b_detail = bl_details_list[0]
                if cur_catalog_id is None : cur_catalog_id = b_detail.get("CatalogId")
                if cur_repo_id is None : cur_repo_id = b_detail.get("RepositoryId")
                if cur_catalog_id: cur_catalog_id = int(cur_catalog_id)
                if cur_repo_id: cur_repo_id = int(cur_repo_id)
        if not all([cur_baseline_id, cur_catalog_id, cur_repo_id]):
            logger_instance.error("BaselineID, CatalogID, or RepoID undetermined for firmware update."); return False

    update_actions_str_or_list = firmware_task_input.get('update_actions', 'UPGRADE')
    desired_actions = set()
    if isinstance(update_actions_str_or_list, str):
        if update_actions_str_or_list.lower() == "flash-all": desired_actions.update(["UPGRADE", "DOWNGRADE"])
        else: desired_actions.add(update_actions_str_or_list.upper())
    elif isinstance(update_actions_str_or_list, list):
        for act in update_actions_str_or_list:
            if isinstance(act, str): desired_actions.add(act.upper())
    if not desired_actions or not all(act in constants.VALID_FIRMWARE_UPDATE_ACTIONS for act in desired_actions):
        logger_instance.error(f"Invalid 'update_actions': {update_actions_str_or_list}."); return False
    
    logger_instance.info(f"Checking compliance for baseline ID {cur_baseline_id}, actions: {desired_actions}...")
    compliance_items = ome_client_instance.get_baseline_compliance_report(cur_baseline_id) # type: ignore
    if compliance_items is None: logger_instance.error("Failed to get compliance report."); return False
    if not compliance_items: logger_instance.info("No devices in compliance report or all compliant."); return True

    dev_ids_in_report = list(set(int(item['DeviceId']) for item in compliance_items if item.get('DeviceId') is not None))
    dev_details_map = {}
    if dev_ids_in_report:
        dev_type_map = {int(dt['DeviceType']): dt['Name'] for dt in ome_client_instance.get_device_type_details() or [] if dt.get("DeviceType") is not None} # type: ignore
        devices_data = ome_client_instance.get_devices_by_ids(dev_ids_in_report) # type: ignore
        if devices_data:
            for dev in devices_data:
                d_id, d_type_id = dev.get("Id"), dev.get("Type")
                if d_id is not None and d_type_id is not None:
                    dev_details_map[d_id] = {"Type": {"Id": d_type_id, "Name": dev_type_map.get(d_type_id, "Unknown")}}
    
    targets_for_fw_job = []
    for dev_comp_info in compliance_items:
        dev_id = dev_comp_info.get("DeviceId")
        if dev_id is None: continue; dev_id = int(dev_id)
        comp_to_update_src_names = [cr["SourceName"] for cr in dev_comp_info.get('ComponentComplianceReports', []) if cr.get("UpdateAction", "").upper() in desired_actions]
        if comp_to_update_src_names:
            if dev_id not in dev_details_map: logger_instance.warning(f"No type details for DeviceID {dev_id}. Skipping for FW update."); continue
            targets_for_fw_job.append({"Id": dev_id, "TargetType": dev_details_map[dev_id]["Type"], "Data": ";".join(comp_to_update_src_names)})
    
    if not targets_for_fw_job: logger_instance.info("No components require specified update actions."); return True

    update_task_job_type_id = ome_client_instance.get_job_type_id_by_name("Update_Task") # type: ignore
    if not update_task_job_type_id: logger_instance.error("Cannot find JobType ID for 'Update_Task'."); return False

    job_name = firmware_task_input.get('job_name_prefix', f"FWUpdate_BL{cur_baseline_id}") + f"_{time.strftime('%Y%m%d%H%M%S')}"
    fw_job_payload = {
        "JobName": job_name, "JobDescription": firmware_task_input.get('job_description', f"FW update for BL {cur_baseline_id}"),
        "Schedule": "startNow", "State": "Enabled", "JobType": {"Id": update_task_job_type_id, "Name": "Update_Task"},
        "Params": [
            {"Key": "complianceReportId", "Value": str(cur_baseline_id)}, {"Key": "repositoryId", "Value": str(cur_repo_id)},
            {"Key": "catalogId", "Value": str(cur_catalog_id)}, {"Key": "operationName", "Value": "INSTALL_FIRMWARE"},
            {"Key": "complianceUpdate", "Value": "true"}, {"Key": "signVerify", "Value": "true"}, # Defaults
            {"Key": "stagingValue", "Value": "true" if firmware_task_input.get('stage_update', False) else "false"}
        ], "Targets": targets_for_fw_job
    }
    if firmware_task_input.get('reboot_needed_action'): fw_job_payload["Params"].append({"Key": "RebootNeededAction", "Value": firmware_task_input['reboot_needed_action']})
    
    logger_instance.info(f"Creating FW update job: '{job_name}' for {len(targets_for_fw_job)} targets.")
    logger_instance.debug(f"FW update job payload: {json.dumps(fw_job_payload, indent=2)}")
    update_job_info = ome_client_instance.create_firmware_update_job(fw_job_payload) # type: ignore
    if not update_job_info or not update_job_info.get("Id"): logger_instance.error("Failed to create FW update job."); return False
    update_job_id = update_job_info["Id"]; logger_instance.info(f"FW update job '{job_name}' created. ID: {update_job_id}.")
    if not track_ome_job_completion(ome_client_instance, update_job_id, f"FW Update Job '{job_name}'", logger_instance):
        logger_instance.error(f"FW update job '{job_name}' (ID: {update_job_id}) failed/timed out."); return False
    logger_instance.info(f"FW update job '{job_name}' (ID: {update_job_id}) completed.")

    if cur_comp_job_id: # If original baseline compliance job ID is known
        logger_instance.info(f"Attempting rerun of baseline compliance job (Original ID: {cur_comp_job_id}) post-update...")
        rerun_info = ome_client_instance.rerun_job(cur_comp_job_id) # type: ignore
        if rerun_info:
            new_comp_job_id = rerun_info.get("Id", cur_comp_job_id) 
            if new_comp_job_id: track_ome_job_completion(ome_client_instance, new_comp_job_id, f"Post-Update Compliance Job {new_comp_job_id}", logger_instance)
            else: logger_instance.info("Compliance job rerun initiated (no new job ID).")
        else: logger_instance.warning(f"Could not initiate rerun of compliance job {cur_comp_job_id}.")
    else: logger_instance.info("Initial compliance job ID not available, skipping post-update compliance rerun.")
    logger_instance.info("--- Finished Firmware Update process ---")
    return True
#------------------
  # --- NEW: Firmware Update Workflow CLI Arguments ---
    grp_fw = parser.add_argument_group('Firmware Update Workflow Parameters')
    grp_fw.add_argument(f'--{constants.CATALOG_TASK_CLI_ARG_NAME.replace("_","-")}', dest='catalog_task_cli', metavar='JSON_STRING', help="JSON for new catalog creation (keys: repo_type, etc.).")
    grp_fw.add_argument(f'--{constants.CATALOG_NAME_CLI_ARG_NAME.replace("_","-")}', dest='catalog_name_cli', metavar='CATALOG_NAME', help="Name of an existing catalog to use or find.")
    grp_fw.add_argument(f'--{constants.CATALOG_REFRESH_FLAG_CLI_ARG_NAME.replace("_","-")}', dest='refresh_catalog_cli', action='store_true', help="Force refresh of the specified existing catalog.")
    grp_fw.add_argument(f'--{constants.BASELINE_TASK_CLI_ARG_NAME.replace("_","-")}', dest='baseline_task_cli', metavar='JSON_STRING', help="JSON for new baseline creation (keys: baseline_name, catalog_name_or_id, targets, etc.).")
    grp_fw.add_argument(f'--{constants.BASELINE_NAME_CLI_ARG_NAME.replace("_","-")}', dest='baseline_name_cli', metavar='BASELINE_NAME', help="Name of an existing baseline to use for firmware update.")
    grp_fw.add_argument(f'--{constants.FIRMWARE_UPDATE_TASK_CLI_ARG_NAME.replace("_","-")}', dest='firmware_update_task_cli', metavar='JSON_STRING', help="JSON for firmware update job parameters (keys: baseline_name_or_id, update_actions, stage_update, etc.).")
    grp_fw.add_argument(f'--{constants.FW_TARGET_GROUPNAME_CLI_ARG.replace("_","-")}', dest='fw_target_groupname_cli', metavar='GROUP_NAME', help="Target group name for firmware update (overrides baseline task targets).")
    grp_fw.add_argument(f'--{constants.FW_TARGET_SERVICETAGS_CLI_ARG.replace("_","-")}', dest='fw_target_servicetags_cli', metavar='TAG1,...', help="Comma-separated service tags for firmware update.")
    grp_fw.add_argument(f'--{constants.FW_TARGET_IDRACIPS_CLI_ARG.replace("_","-")}', dest='fw_target_idracips_cli', metavar='IP1,...', help="Comma-separated iDRAC IPs for firmware update.")
    grp_fw.add_argument(f'--{constants.FW_TARGET_DEVICENAMES_CLI_ARG.replace("_","-")}', dest='fw_target_devicenames_cli', metavar='NAME1,...', help="Comma-separated device names for firmware update.")
    grp_fw.add_argument(f'--{constants.FW_TARGET_DEVICEIDS_CLI_ARG.replace("_","-")}', dest='fw_target_deviceids_cli', metavar='ID1,...', help="Comma-separated OME device IDs for firmware update.")
    #--------------------
     # --- NEW: Catalog Management ---
    if run_all or args.run_catalog_management:
        logger.info("--- Preparing for Catalog Management ---")
        catalog_task_def = utils.get_single_input(args.catalog_task_cli, config, constants.CATALOG_CONFIG_SECTION, logger, is_json_string_cli=True)
        catalog_name_to_use = args.catalog_name_cli # Prioritize CLI name for finding/refreshing
        refresh_catalog_flag = args.refresh_catalog_cli
        
        # If task def is provided, it's for creation. If only name, it's for find/refresh.
        if catalog_task_def:
            # TODO: Validate catalog_task_def using input_validator.validate_catalog_creation_task_specific
            logger.info("Processing new catalog creation task from input.")
            success, cat_id, repo_id = handle_catalog_management(ome_client_instance, catalog_task_def, None, False, logger)
            if success and cat_id is not None: catalog_id_for_fw, repo_id_for_fw = cat_id, repo_id
            else: overall_script_success = False
        elif catalog_name_to_use: # Manage existing catalog by name
            logger.info(f"Managing existing catalog by name: '{catalog_name_to_use}', Refresh: {refresh_catalog_flag}")
            success, cat_id, repo_id = handle_catalog_management(ome_client_instance, None, catalog_name_to_use, refresh_catalog_flag, logger)
            if success and cat_id is not None: catalog_id_for_fw, repo_id_for_fw = cat_id, repo_id
            else: overall_script_success = False # Finding/refreshing failed
        elif run_all or args.run_catalog_management: # Flag set but no data
            logger.info("Catalog management requested but no creation task or existing catalog name provided. Skipping.")
    
    # --- NEW: Baseline Management ---
    if run_all or args.run_baseline_management:
        logger.info("--- Preparing for Baseline Management ---")
        baseline_task_def = utils.get_single_input(args.baseline_task_cli, config, constants.BASELINE_CONFIG_SECTION, logger, is_json_string_cli=True)
        baseline_name_to_use = args.baseline_name_cli

        if baseline_task_def: # Create new baseline
            logger.info("Processing new baseline creation task from input.")
            # TODO: Validate baseline_task_def using input_validator.validate_baseline_creation_task_specific
            # Catalog ID/Repo ID for new baseline can come from previous step or from within baseline_task_def itself
            cat_id_for_new_baseline = catalog_id_for_fw
            repo_id_for_new_baseline = repo_id_for_fw
            if 'catalog_name_or_id' in baseline_task_def and (cat_id_for_new_baseline is None): # If not from prev step, resolve from task
                # Logic to resolve catalog_name_or_id from task to actual IDs would be needed here
                # For now, assume it's passed if creating baseline after catalog.
                logger.warning("Baseline creation task needs catalog_name_or_id, ensure it's resolvable or provided by previous catalog step.")

            success, base_id, comp_job_id = handle_baseline_management(ome_client_instance, baseline_task_def, None, cat_id_for_new_baseline, repo_id_for_new_baseline, logger)
            if success and base_id is not None: baseline_id_for_fw, compliance_job_id_for_fw = base_id, comp_job_id
            else: overall_script_success = False
        elif baseline_name_to_use: # Use existing baseline by name
             logger.info(f"Managing existing baseline by name: '{baseline_name_to_use}'")
             success, base_id, comp_job_id = handle_baseline_management(ome_client_instance, None, baseline_name_to_use, None, None, logger) # Catalog/repo IDs not needed to find existing
             if success and base_id is not None: baseline_id_for_fw, compliance_job_id_for_fw = base_id, comp_job_id
             else: overall_script_success = False
        elif run_all or args.run_baseline_management:
            logger.info("Baseline management requested but no creation task or existing baseline name provided. Skipping.")

    # --- NEW: Firmware Update ---
    if run_all or args.run_firmware_update:
        logger.info("--- Preparing for Firmware Update ---")
        fw_update_task_params = utils.get_single_input(args.firmware_update_task_cli, config, constants.FIRMWARE_UPDATE_CONFIG_SECTION, logger, is_json_string_cli=True)
        
        if not fw_update_task_params: # If no task definition, this operation cannot proceed
            if run_all or args.run_firmware_update: logger.warning("Firmware update requested, but no task parameters provided via --firmware-update-task or config. Skipping.");
        else:
            # Baseline ID for firmware update:
            # 1. From previous baseline step (baseline_id_for_fw)
            # 2. From 'baseline_name_or_id' in fw_update_task_params
            # 3. From --baseline-name CLI arg (args.baseline_name_cli)
            current_baseline_id_for_fw = baseline_id_for_fw or \
                                         (int(fw_update_task_params['baseline_name_or_id']) if isinstance(fw_update_task_params.get('baseline_name_or_id'), int) else None)
            baseline_name_ref_for_fw = args.baseline_name_cli or \
                                       (fw_update_task_params.get('baseline_name_or_id') if isinstance(fw_update_task_params.get('baseline_name_or_id'), str) else None)

            # If baseline_id_for_fw is still None, try to resolve from name
            if current_baseline_id_for_fw is None and baseline_name_ref_for_fw:
                logger.info(f"Baseline ID for firmware update not available. Looking up by name: '{baseline_name_ref_for_fw}'")
                success_bl_find, b_id, c_job_id = handle_baseline_management(ome_client_instance, None, baseline_name_ref_for_fw, None, None, logger)
                if success_bl_find and b_id: current_baseline_id_for_fw, compliance_job_id_for_fw = b_id, c_job_id
                else: logger.error(f"Could not resolve baseline '{baseline_name_ref_for_fw}' for firmware update.")
            
            # We also need catalog_id and repo_id for the firmware update job.
            # Try to use from previous catalog step, or fetch from baseline details if necessary.
            final_catalog_id = catalog_id_for_fw
            final_repo_id = repo_id_for_fw

            if current_baseline_id_for_fw and (final_catalog_id is None or final_repo_id is None):
                logger.info(f"Fetching details for baseline ID {current_baseline_id_for_fw} to get catalog/repo IDs for firmware update.")
                bl_details_list = ome_client_instance.get_baselines(baseline_id_filter=current_baseline_id_for_fw) # type: ignore
                if bl_details_list and bl_details_list[0]:
                    bl_detail = bl_details_list[0]
                    if final_catalog_id is None : final_catalog_id = bl_detail.get("CatalogId")
                    if final_repo_id is None : final_repo_id = bl_detail.get("RepositoryId")
                    if final_catalog_id: final_catalog_id = int(final_catalog_id)
                    if final_repo_id: final_repo_id = int(final_repo_id)
                else: logger.error(f"Could not fetch details for baseline ID {current_baseline_id_for_fw} to get catalog/repo IDs.")
            
            # Override targets in fw_update_task_params if CLI target args are provided
            # This part of logic should be inside handle_firmware_update or use a helper
            # For now, assume fw_update_task_params is complete or targets are resolved by baseline.
            # The original script resolved targets inside baseline_creation and then used them for compliance check and update.
            # Here, the firmware update task might define its own targets or rely on the baseline's targets.
            # For simplicity, handle_firmware_update will get compliance for all devices in baseline.

            if current_baseline_id_for_fw and final_catalog_id and final_repo_id:
                # TODO: Validate fw_update_task_params using input_validator.validate_firmware_update_task_specific
                if not handle_firmware_update(ome_client_instance, fw_update_task_params, 
                                              current_baseline_id_for_fw, final_catalog_id, final_repo_id, 
                                              compliance_job_id_for_fw, logger):
                    overall_script_success = False
            elif run_all or args.run_firmware_update:
                logger.warning("Firmware update requested, but prerequisite IDs (baseline, catalog, repo) or task params are missing. Skipping.")
