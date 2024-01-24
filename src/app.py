#!/usr/bin/env python3
"""
Copyright (c) 2023 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Danielle Stacy <dastacy@cisco.com>, Jorge Banegas <jbanegas@cisco.com>, Trevor Maco <tmaco@cisco.com>"
__copyright__ = "Copyright (c) 2023 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

# Import Section
import datetime
import json
import logging
import os
from logging.handlers import TimedRotatingFileHandler
from urllib.parse import parse_qs

import meraki
import requests
import rich.logging
from dotenv import load_dotenv
from flask import Flask, render_template, url_for
from flask import request, jsonify
from flask_caching import Cache

# Absolute Paths
script_dir = os.path.dirname(os.path.abspath(__file__))
logs_path = os.path.join(script_dir, 'logs')

# Load in Environment Variables
load_dotenv()
MERAKI_API_KEY = os.getenv('MERAKI_API_KEY')

# Meraki Dashboard Instance
dashboard = meraki.DashboardAPI(api_key=MERAKI_API_KEY, suppress_logging=True)

# Set up logging
logger = logging.getLogger('my_logger')
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s %(levelname)s: %(funcName)s:%(lineno)d - %(message)s')

# log to stdout
stream_handler = rich.logging.RichHandler()
stream_handler.setLevel(logging.INFO)

# log to files (last 7 days, rotated at midnight local time each day)
log_file = os.path.join(logs_path, 'portal_logs.log')
file_handler = TimedRotatingFileHandler(log_file, when="midnight", interval=1, backupCount=7)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# Global variables
app = Flask(__name__)

# Configuring Flask-Caching
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# Global Structures
progress = 0
display_errors = {}
networkIDtoNameMapping = {}
networkNametoIdMapping = {}


# Methods
def getSystemTimeAndLocation():
    """
    Return location and time of accessing device (used on all webpage footers)
    :return:
    """
    # request user ip
    userIPRequest = requests.get('https://get.geojs.io/v1/ip.json')
    userIP = userIPRequest.json()['ip']

    # request geo information based on ip
    geoRequestURL = 'https://get.geojs.io/v1/ip/geo/' + userIP + '.json'
    geoRequest = requests.get(geoRequestURL)
    geoData = geoRequest.json()

    # create info string
    location = geoData['country']
    timezone = geoData['timezone']
    current_time = datetime.datetime.now().strftime("%d %b %Y, %I:%M %p")
    timeAndLocation = "System Information: {}, {} (Timezone: {})".format(location, current_time, timezone)

    return timeAndLocation


@cache.memoize(timeout=300)  # Cache the result for 5 minutes
def dropdown():
    """
    Return Drop Down Content (wrapped in method to support new networks and organizations) - cached
    :return: A list of orgs and the corresponding networks
    """
    dropdown_content = []
    networkIDtoNameMapping.clear()
    networkNametoIdMapping.clear()

    organizations = dashboard.organizations.getOrganizations()
    sorted_organizations = sorted(organizations, key=lambda x: x['name'])

    logger.info(f"Found the following orgs: {sorted_organizations}")

    # Build drop down menus for organization and network selection (the available options in the left hand menu bar)
    for organization in sorted_organizations:
        org_data = {'orgaid': organization['id'], 'organame': organization['name']}
        try:
            networks = dashboard.organizations.getOrganizationNetworks(organization['id'], total_pages='all')
            network_data = []
            for network in networks:
                if 'wireless' in network['productTypes']:
                    network_data.append({'networkid': network['id'], 'networkname': network['name']})

                    # Add Network ID to global lists
                    networkIDtoNameMapping[network['id']] = network['name']
                    networkNametoIdMapping[network['name']] = network['id']

            org_data['networks'] = network_data
            dropdown_content.append(org_data)
        except Exception as e:
            logger.error(
                f"Error retrieving networks for organization {organization['name']} with ID {organization['id']}: {e}")

    return dropdown_content


@cache.memoize(timeout=120)  # Cache the result for 2 minutes
def ssid_to_tag_mapping(selected_organization, selected_networks):
    """
    Execute main workflow to identify SSIDs that correspond to AP tags within various networks.
    Return a list of SSID and the networks to map them too. Results are cached for faster copying of SSIDs to networks.
    :param selected_organization: Selected organization to search for mappings in
    :param selected_networks: Selected network(s) to search for mappings in
    :return: A dict of SSID's in each network, Dict of SSIDs mapped to AP Tags
    """
    global progress
    progress = 0

    logger.info("Started SSID to Tag Mapping Logic...")

    # Get all Wireless Networks in Org
    wireless_networks = get_wireless_networks(selected_organization)
    # Sort Wireless Networks by Network Name (this guarantees duplicate SSID names result in the first Network's SSID
    # configuration bein copied over)
    wireless_networks = sorted(wireless_networks, key=lambda device: device['name'])

    logger.info(f"Found {len(wireless_networks)} total wireless networks in the org.")
    progress = 25

    # Retrieve all the configured SSIDs from the Meraki organization
    all_ssids = get_all_ssids(wireless_networks)
    logger.info(f"Found {len(all_ssids)} total SSIDs in the org.")
    progress = 50

    ssid_dict = make_ssid_dict(all_ssids)

    # Retrieve all the SSID names that correspond to the AP tags
    network_to_ssids = {}
    progress_inc = 50 / float(len(selected_networks))
    for net_id in selected_networks:
        network_to_ssids[net_id] = get_ap_ssids(selected_organization, net_id, all_ssids)
        progress += progress_inc

    progress = 100
    logger.info(f'The following mappings were identified: {network_to_ssids}')

    # Return the 2 data structures needed for applying the ssid's to the ap's with the corresponding tags
    return ssid_dict, network_to_ssids


def ssid_overview_data(selected_network):
    """
    Get a list of SSIDs in the selected network.
    :param selected_network: Selected network
    :return: A list of SSIDs
    """
    try:
        ssids = dashboard.wireless.getNetworkWirelessSsids(selected_network)
        logger.info(f"Found {len(ssids)} SSIDs in network {selected_network}!")
        return ssids
    except Exception as e:
        logger.error(f"Exception raised: {str(e)}")
        return []


def ap_overview_data(selected_organization, selected_network):
    """
    Get a list of APs in the selected network, return information about them plus their current online status.
    :param selected_organization: Selected Organization
    :param selected_network: Selected Network
    :return: A list of APs
    """
    global progress

    # Get AP Data
    access_points = []
    try:
        progress = 0

        # Grab all Access Points from the selected network.
        devices_in_network = dashboard.networks.getNetworkDevices(selected_network)
        progress = 25

        # Get Device network statuses, set status field in devices list
        statuses = dashboard.organizations.getOrganizationDevicesStatuses(selected_organization, total_pages='all',
                                                                          networkIds=[selected_network])
        progress = 50

        device_status = {}
        for status in statuses:
            device_status[status['name']] = status['status']

        progress = 75

        for device in devices_in_network:
            if device['model'].startswith('MR'):
                # Modify tags for display
                device['tags'] = ', '.join(device['tags'])
                access_points.append(device)

                # Set status field per each device
                device['status'] = device_status[status['name']]

        logger.info(f"Found {len(access_points)} Access Points in network {selected_network}!")

    except Exception as e:
        logger.error(f"Exception raised: {str(e)}")

    progress = 100
    return access_points


def get_wireless_networks(org_id):
    """
    Connect to the Meraki dashboard and retrieve all the wireless networks in
    the org
    :param org_id: Org ID
    :return: list containing the details of each of the wireless networks
    """
    networks = dashboard.organizations.getOrganizationNetworks(org_id,
                                                               total_pages="all")
    wireless_networks = []
    for network in networks:
        if "wireless" in network["productTypes"]:
            wireless_networks.append(network)

    return wireless_networks


def get_all_ssids(wireless_networks):
    """
    Iterate through the list of wireless networks and retrieve all the SSIDs
    for each network. Add the SSIDs to a list if it is not an Unconfigured SSID
    :param wireless_networks: A list of networks to retrieve SSIDs for
    :return: list containing the details of the configured SSIDs
    """
    all_ssids = []
    for net in wireless_networks:
        logger.info(f"Retrieving SSIDs for the {net['name']} network")
        ssids = dashboard.wireless.getNetworkWirelessSsids(net["id"])
        for ssid in ssids:
            if not ssid["name"].startswith("Unconfigured"):
                ssid['sourceNetworkName'] = net['name']
                all_ssids.append(ssid)

    return all_ssids


def make_ssid_dict(ssids):
    """
    Iterate through the SSIDs and create a dictionary that maps the SSID name
    to the details of the SSID
    :param ssids: A list of SSIDs
    :return: dictionary with keys that are the names of the SSIDs and the SSID details as the values
    """
    ssid_dict = {}
    for ssid in ssids:
        name = ssid["name"]
        # Only add the first instance of a SSID (first alphabetical network)
        if name not in ssid_dict:
            ssid_dict[name] = ssid

    return ssid_dict


def get_ap_ssids(org_id, net_id, ssids):
    """
    Get all the AP tags in the network that correspond to existing SSID names
    :param org_id: Org ID
    :param net_id: Network ID
    :param ssids: a list of SSIDs
    :return: set of the AP tag names that correspond to existing SSID names
    """
    network_ssids = set()
    for ssid in ssids:
        tag = ssid["name"]
        logger.info(f"Retrieving all APs with the tag {tag}")
        aps = dashboard.organizations.getOrganizationDevices(org_id,
                                                             total_pages="all",
                                                             networkIds=[net_id],
                                                             tags=[tag],
                                                             tagsFilterType="withAnyTags",
                                                             productTypes=["wireless"])
        # Build the lit of AP's with SSID names as their tag in each network
        for ap in aps:
            network_ssids.add(tag)

    return network_ssids


def configure_net_ssids(net_id, ssid_config):
    """
    Configure an SSID in the network
    :param net_id: Network ID
    :param ssid_config: SSID config to apply to the network
    :return: Boolean value indicating whether the SSID was successfully configured
    """
    global display_errors
    ssid_config["number"] = 3  # the SSID configured will always be the 4th SSID (0-based index)
    ssid_num = ssid_config.pop("number")
    try:
        response = dashboard.wireless.updateNetworkWirelessSsid(net_id, ssid_num, **ssid_config)
        logger.info(f"{networkIDtoNameMapping[net_id]} configured with ssid {ssid_config['name']}")
    except Exception as e:
        logger.error(
            f"There was an issue configuring the SSID {ssid_config['name']} for the following reason: {str(e)}")

        # Display List of SSID Errors per Network
        if networkIDtoNameMapping[net_id] in display_errors:
            display_errors[networkIDtoNameMapping[net_id]].append(str(e))
        else:
            display_errors[networkIDtoNameMapping[net_id]] = [str(e)]


# Routes
@app.route('/progress')
def get_progress():
    """
    Get current process progress for progress bar display
    """
    global progress

    # Return the progress as a JSON response
    return jsonify({'progress': progress})


@app.route('/wireless_overview')
def wireless_overview():
    """
    Showcase "overview" of APs and SSID's in the selected organization and network on the landing page.
    """
    logger.info(f'Wireless Overview {request.method} Request:')

    # Extract which org and network (ids) were selected in the drop-down
    selected_organization = request.args.get('organizations_select')
    selected_network = request.args.get('networks_select')
    logger.info(f'Selected Org: {selected_organization}, Selected Network: {selected_network}')

    # Call the various function with the selected parameters to return overview data
    wireless_data = {'aps': ap_overview_data(selected_organization, selected_network),
                     'ssids': ssid_overview_data(selected_network)}

    return jsonify(wireless_data)


@app.route('/ssid_mapping', methods=['POST'])
def ssid_mapping():
    """
    Find and return SSID to Tag Mapping (invoked with AJAX call), executes workflow within ssid_to_tag_mapping
    (separated and cached for performance)
    """
    logger.info(f'SSID Table Mapping dictionary {request.method} Request:')

    # Obtain selected org and selected network(s)
    selected_org = request.form.get('organizations_select')
    networks_list = request.form.getlist('networks_select')
    logger.info(f"POST data received from client: {request.form.to_dict()}")

    # Get SSID to Tag Mapping Data (don't apply mappings yet!)
    ssid_dict, network_to_ssids = ssid_to_tag_mapping(selected_org, networks_list)

    mapping_display = []
    # Craft Display table
    for network in network_to_ssids:
        for ssid in network_to_ssids[network]:
            net_name = networkIDtoNameMapping[network]
            ssid_info = ssid_dict[ssid]

            # Get Source Network Name (tagged along for the ride :)), pop it off
            source_network_name = ssid_info['sourceNetworkName']
            del ssid_info['sourceNetworkName']

            mapping_display.append(
                {'ssid_name': ssid, 'source_network': source_network_name, 'enabled': ssid_info['enabled'], 'authMode': ssid_info['authMode'],
                 'dest_network': net_name})

    return jsonify(mapping_display)


@app.route('/ssids', methods=['POST'])
def ssids():
    """
    Find and return SSIDs for the various networks (invoked with AJAX call), executes workflow within ssid_overview_data
    (separated and cached for performance)
    """
    global progress
    logger.info(f'SSIDs {request.method} Request:')

    # Obtain selected network(s)
    networks_list = request.form.getlist('networks_select')
    logger.info(f"POST data received from client: {request.form.to_dict()}")

    progress = 0

    # Get SSID to Tag Mapping Data (don't apply mappings yet!)
    ssids = {}
    progress_inc = 100 / float(len(networks_list))
    for network in networks_list:
        ssids[network] = ssid_overview_data(network)
        progress += progress_inc

    ssid_display = []
    # Craft Display table
    for network in ssids:
        for ssid in ssids[network]:
            net_name = networkIDtoNameMapping[network]
            ssid_display.append(
                {'ssid_name': ssid['name'], 'net_id': network, 'net_name': net_name, 'enabled': ssid['enabled'],
                 'authMode': ssid['authMode'], 'number': ssid['number']})

    progress = 100
    return jsonify(ssid_display)


@app.route('/')
def index():
    """
    Main landing page: display AP and SSID overviews per network
    """
    logger.info(f'Index {request.method} Request:')

    dropdown_content = dropdown()
    return render_template('index.html', dropdown_content=dropdown_content, hiddenLinks=False,
                           timeAndLocation=getSystemTimeAndLocation())


@app.route('/ssid_to_tag', methods=['GET', 'POST'])
def ssid_to_tag():
    """
    SSID to Tag Mapping page. Displays Mappings and executes application of identified mappings on POST request.
    """
    global progress

    logger.info(f'SSID to Tag {request.method} Request:')

    dropdown_content = dropdown()
    success = False

    # Handle the form submission when user selects specific devices and updates them.
    if request.method == 'POST':
        logger.info(f"POST data received from client: {request.form.to_dict()}")
        progress = 0
        display_errors.clear()

        # Obtain selected org and selected network(s)
        selected_org = request.form.get('organizations_select')
        networks_list = request.form.get('networks_select')
        networks_list = networks_list.split(',')

        # Get SSID to Tag Mapping Data (don't apply mappings yet!)
        ssid_dict, network_to_ssids = ssid_to_tag_mapping(selected_org, networks_list)

        # Calculate progress increment (100 / length floored)
        progress_inc = 100 / float(sum(len(value) for value in network_to_ssids.values()))

        for net_id in network_to_ssids:
            logger.info(f"Configuring the SSIDs of the {networkIDtoNameMapping[net_id]} network")
            for ssid_name in network_to_ssids[net_id]:
                ssid = ssid_dict[ssid_name]
                # Apply SSID to target network
                configure_net_ssids(net_id, ssid)
                progress += progress_inc

        progress = 100
        success = True

    return render_template('ssidToTag.html', dropdown_content=dropdown_content, display_errors=display_errors,
                           success=success, hiddenLinks=False, timeAndLocation=getSystemTimeAndLocation())


@app.route('/configure_ssid', methods=['GET', 'POST'])
def configure_ssid():
    """
    Configure SSIDs Page. Display SSIDs and apply changes to selected SSIDs based on selections and dropdowns.
    """
    global progress, display_errors
    logger.info(f'Configure SSID {request.method} Request:')

    dropdown_content = dropdown()

    # If success is present (during redirect after successfully updating SSID), extract URL param
    if request.args.get('success'):
        success = request.args.get('success')
    else:
        # Clear any previous upload errors, start fresh
        display_errors.clear()
        success = False

    # Handle the form submission when user selects specific devices and updates them.
    if request.method == 'POST':
        logger.info(f"POST data received from client: {request.form.to_dict()}")
        progress = 0
        display_errors.clear()

        # Obtain selected SSIDs
        table_data = request.form.get('table_data')
        table_data = json.loads(table_data)

        # Retrieve ssid config data from form
        form_data = request.form.get('form_data')
        form_data = parse_qs(form_data, keep_blank_values=True)

        # Dictionary of variable params for API call
        kwargs = {}

        # Retrieve Values from Form
        enabled = form_data['ssid_state'][0]
        kwargs['enabled'] = True if enabled == 'enabled' else False

        name = form_data['ssid_name'][0]
        if name != '' and name:
            kwargs['name'] = name

        # Auth related fields
        auth_mode = form_data['auth'][0]
        if auth_mode != '-- Existing --':
            kwargs['authMode'] = auth_mode

            # PSK Related Fields
            if kwargs['authMode'] == 'psk':
                kwargs['psk'] = form_data['password'][0]
                kwargs['encryptionMode'] = form_data['encryption'][0]

        # Calculate progress increment (100 / length floored)
        progress_inc = 100 / float(len(table_data))

        # Update SSIDs
        for ssid in table_data:
            net_id = networkNametoIdMapping[ssid['netName']]

            # Response uses kwargs dictionary, provides whatever parameters present (absence of which results
            # in existing values kept - API field dependant!)
            try:
                response = dashboard.wireless.updateNetworkWirelessSsid(net_id, ssid['number'], **kwargs)
            except Exception as e:
                # Display List of SSID Errors per Network
                if ssid['netName'] in display_errors:
                    display_errors[ssid['netName']].append(str(e))
                else:
                    display_errors[ssid['netName']] = [str(e)]

                logger.error(f"Error updating network SSIDs, {str(e)}")

            progress += progress_inc

        progress = 100
        # Support AJAX redirect to display success message and update display tables on screen
        return jsonify({'redirect_url': url_for('configure_ssid', success=True)})

    return render_template('configure_ssid.html', dropdown_content=dropdown_content, success=success,
                           display_errors=display_errors, hiddenLinks=False,
                           timeAndLocation=getSystemTimeAndLocation())


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)
