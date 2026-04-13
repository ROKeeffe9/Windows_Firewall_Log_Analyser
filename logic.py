import re
import geoip2.database
import geoip2.errors
import ipaddress
import socket
from datetime import datetime, timedelta
import math

try:
    reader = geoip2.database.Reader('Geo/GeoLite2-City.mmdb')
except FileNotFoundError:
    raise RuntimeError("GeoLite2 database not found. See README for setup instructions.")


ip_cache = {}

def load_malicious_addresses(filepath):

    """
    Load in the malicious IP address list into two sets.

    Args:
        filepath to the malicious IP address file.

    Returns:
        tuple:
            - ip_set (set): Set of individual IP addresses.
            - networks (list): List of IP addresses with CIDR.
    """

    ip_set = set()
    networks = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Take out comment lines
            if line.startswith("#"):
                continue

            # If it contains CIDR - put in networks, otherwise put in ip_set for basic checks
            if "/" in line:
                networks.append(ipaddress.ip_network(line))
            else:
                ip_set.add(line)

    return ip_set, networks

ip_set, networks = load_malicious_addresses('Firehol/firehol_level1.netset')


def file_to_list(input_file):

    """
    Turns an input file into list of dictionaries with headers as keys.

    Args:
        An input file.

    Returns:
        list: logs
                - A list of dictionaries where each dictionary represents a log entry.
    """

    logs = []
    headers = []

   
    for line in input_file:
        dec_line = line.decode("utf-8", errors="ignore")

        # Strip null bytes (\x00) which appear in some firewall logs
        dec_line = dec_line.replace("\x00", "").strip()

        if not dec_line:
            continue

        part = re.split(r"\s+", dec_line)
        if part:

            # If first string is "#Fields" - the next will be the headers
            if part [0] == "#Fields:":
                headers = part[1:]

            # If is doesn't start with # -> it will be the logs or empty lines
            elif part[0][0] != "#":
                if len(part) != len(headers):
                    return None
                single_log = {}
                for i in range(len(part)):
                    single_log[headers[i]] = part[i]
                logs.append(single_log)

    return logs



def get_filter_config(logs):

    """
    Retrieves a dictionary of dictionaries with preconfigured key value pairs 
    which dictate how each fields filter box will be handled.

    Args:
        logs (list): List of log dictionaries..

    Returns:
        Dictionary: (filter_config)
                    - filter_config: A dictionary of dictionaries used to create filter boxes dynamically:
    """

    # This is the configuration data for how filter boxes will be displayed and treated
    # -> general, in a range, or with a drop box
    filter_config = {
        "date": {
            "field": "date",
            "type": "date",
            "input": "range"
        },
        "time": {
            "field": "time",
            "type": "time",
            "input": "range"
        },
        "action": {
            "field": "action",
            "input": "categorical"
        },
        "protocol": {
            "field": "protocol",
            "input": "categorical"
        },
        "src-ip": {
            "field": "src-ip",
            "type": "text",
            "input": "general"
        },
        "dst-ip": {
            "field": "dst-ip",
            "type": "text",
            "input": "general"
        },
        "src-port": {
            "field": "src-port",
            "type": "text",
            "input": "general"
        },
        "dst-port": {
            "field": "dst-port",
            "type": "text",
            "input": "general"
        },
        "size": {
            "field": "size",
            "type": "number",
            "input": "range"
        },
        "tcpflags": {
            "field": "tcpflags",
            "type": "text",
            "input": "general"
        },
        "tcpsyn": {
            "field": "tcpsyn",
            "type": "text",
            "input": "general"
        },
        "tcpack": {
            "field": "tcpack",
            "type": "text",
            "input": "general"
        },
        "tcpwin": {
            "field": "tcpwin",
            "type": "text",
            "input": "general"
        },
        "icmptype": {
            "field": "icmptype",
            "type": "text",
            "input": "general"
        },
        "icmpcode": {
            "field": "icmpcode",
            "type": "text",
            "input": "general"
        },
        "info": {
            "field": "info",
            "type": "text",
            "input": "general"
        },
        "path": {
            "field": "path",
            "input": "categorical"
        },
        "pid": {
            "field": "pid",
            "type": "text",
            "input": "general"
        }
    }

    # Get the options for the categorical data drop boxes - unique values
    for config in filter_config.values():

        if config.get("input") == "categorical":

            unique_values = set()

            for log in logs:
                val = log.get(config["field"])
                if val:
                    unique_values.add(val)
            
            config["dropdown_list"] = sorted(unique_values)

    return filter_config
        

       

    
def pop_filter_data(form, filter_config):

    """
    Generates a dictionary with standardised information collected from user inputs on how to filter logs

    Args:
        form: A form submitted by the user
        filter_config: dict created by get_filter_config function

    Returns:
        Dictionary: (filter_data) 
                    - filter_data: contains information on how to filter logs:
    """

    filter_data = {}

    for key, config in filter_config.items():

        field = config["field"]

        # For range filters
        if config["input"] == "range":
            filter_data[f"{field}_min"] = (
                form.get(f"{field}_min"),
                "min_range",
                field
            )
            filter_data[f"{field}_max"] = (
                form.get(f"{field}_max"),
                "max_range",
                field
            )
        
        # For categorical filters
        elif config["input"] == "categorical":
            filter_data[field] = (
                form.get(f"{field}_val"),
                "contains",
                field
            )
      
        # For general filters
        else:  
            filter_data[field] = (
                form.get(f"{field}_val"),
                "contains",
                field
            )

    return filter_data


def filter_logs(logs, filter_data):

    """
    Filters the list (logs) down based on parameters in filter_data dictionary

    Args:
        logs: A list of dictionaries
        filter_data: dictionary of filter paramaters created by pop_filter_data function

    Returns:
        List: (filtered_logs) 
                - filtered_logs: A filtered list of dictionaries
    """

    filtered_logs = []

    for log in logs:
        include = True

        for filter_key, (search_value, search_type, field) in filter_data.items():

            # Skip empty filters
            if search_value in [None, "", " "]:
                continue

            log_value = log.get(field)

            if log_value is None:
                include = False
                break

            # Convert to numbers for calculations
            try:
                search_value = float(search_value)
                log_value = float(log_value)
            except:
                pass

            if search_type == "min_range":
                if log_value < search_value:
                    include = False
                    break

            elif search_type == "max_range":
                if log_value > search_value:
                    include = False
                    break

            # For general (partial) search
            elif search_type == "contains":
                if str(search_value) not in str(log_value):
                    include = False
                    break

        if include:
            filtered_logs.append(log)

    return filtered_logs




def add_detail(logs):

    """
    Compute derived attributes from base log info and store them in logs.

    Args:
        logs (list): A list of logs where each log is a dictionary.

    Returns:
        enriched_logs (list): A list of logs with additional key/values for each log
    """
    
    for log in logs:  
    
        # Packet size categories
        packet_size = ""
        if log["size"] != "-":
            size = int(log["size"])
        else:
            size = 0

        if size < 100:
            packet_size = "Very Small"
        elif size < 500:
            packet_size = "Small"
        elif size < 1000:
            packet_size = "Medium"
        elif size <= 1500:
            packet_size = "Large"
        else:
            packet_size = "Very Large"


        # Direction
        direction = ""
        if log["path"] == "RECEIVE":
            direction = "Inbound"
        else:
            direction = "Outbound"


        # IP Details
        src_ip_version, src_ip_type, src_ip_scope, src_ip_country, src_ip_city, src_ip_lat, src_ip_lon, src_ip_trust = ip_details(log["src-ip"])
        dst_ip_version, dst_ip_type, dst_ip_scope, dst_ip_country, dst_ip_city, dst_ip_lat, dst_ip_lon, dst_ip_trust = ip_details(log["dst-ip"])

        # Port Details
        src_port_type, src_port_service = port_details(log["src-port"], log["protocol"])
        dst_port_type, dst_port_service = port_details(log["dst-port"], log["protocol"])


        # Traffic Type
        if log["protocol"] == "TCP" and log["dst-port"] in ["80", "443"]:
            traffic_type = "Web Traffic"

        elif log["protocol"] == "UDP" and log["dst-port"] == "53":
            traffic_type = "DNS Query"

        elif log["protocol"] == "ICMP":
            traffic_type = "Network Test (Ping)"

        else:
            traffic_type = "General Network Traffic"


        

        # Purpose
        if log["action"] == "DROP":
            purpose = "Blocked connection attempt"

        elif log["path"] == "SEND":
            purpose = "Initiated by local system"

        elif log["path"] == "RECEIVE":
            purpose = "External request to system"

        else:
            purpose = "Unknown"

        # Communication pattern
        if log["protocol"] == "TCP" and log["dst-port"] in ["80", "443"]:
            if log["path"] == "SEND":
                pattern = "Client → Web Server"
            else:
                pattern = "Web Server → Client"

        elif log["protocol"] == "UDP" and log["dst-port"] == "53":
            if log["path"] == "SEND":
                pattern = "Client → DNS Server"
            else:
                pattern = "DNS Server → Client"

        elif log["path"] == "RECEIVE" and log["action"] == "DROP":
            pattern = "Blocked Incoming Connection"

        elif log["path"] == "RECEIVE" and src_ip_scope == "Public":
            pattern = "External → Local System"

        elif log["path"] == "SEND" and dst_ip_scope == "Public":
            pattern = "Local → External System"

        else:
            pattern = "General Communication"


        log["extra"] = {
            "packet_size": packet_size,
            "direction": direction,
            "ip_version": src_ip_version,
            "src_ip_type": src_ip_type,
            "src_ip_scope": src_ip_scope,
            "src_ip_country": src_ip_country,
            "src_ip_city": src_ip_city,
            "src_ip_lat": src_ip_lat,
            "src_ip_lon": src_ip_lon,
            "src_ip_trust": src_ip_trust,
            "dst_ip_type": dst_ip_type,
            "dst_ip_scope": dst_ip_scope,
            "dst_ip_country": dst_ip_country,
            "dst_ip_city": dst_ip_city,
            "dst_ip_lat": dst_ip_lat,
            "dst_ip_lon": dst_ip_lon,
            "dst_ip_trust": dst_ip_trust,
            "src_port_type": src_port_type,
            "src_port_service": src_port_service,
            "dst_port_type": dst_port_type,
            "dst_port_service": dst_port_service,
            "traffic_type": traffic_type,
            "purpose": purpose,
            "pattern": pattern
        }
    
    return logs



        

    
def ip_details(ip):

    """
    Analyse an IP address and return detailed metadata.

    Args:
        ip (str): The ip address from a log entry.

    Returns:
        tuple:
            (ip_version, ip_type, ip_scope, ip_country,
             ip_city, ip_lat, ip_lon, ip_trust)

            ip_version: IP version classification ("IPv4" or "IPv6")
            ip_type: Address type (e.g. "Unicast", "Multicast", "Broadcast", or "N/A")
            ip_scope: Network scope classification (e.g. "Public", "Private", "Loopback", etc.)
            ip_country: Country name (or "N/A" if unavailable)
            ip_city: City name (or "N/A" if unavailable)
            ip_lat: Latitude coordinate (or "N/A")
            ip_lon: Longitude coordinate (or "N/A")
            ip_trust: Security classification ("Malicious", "Not Malicious", or "Internal")
    """

    if ip in ip_cache:
        return ip_cache[ip]

    # Ensure it is a valid IP address
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None, None, None, None, None, None, None, None


    # IP Version
    ip_version = ""

    if ":" in ip:
        ip_version = "IPv6"
    else:
        ip_version = "IPv4"


    # IP Type
    # Uses regex to categorise IP addresses based on specific patterns
    ip_type = ""
    if ip_version == "IPv4":
        if ip == "255.255.255.255":
            ip_type = "Broadcast"
        elif re.search(r"^(22[4-9]|23\d)", ip):
            ip_type = "Multicast"
        else:
            ip_type = "Unicast"
    elif ip_version == "IPv6":
        if re.search(r"^ff", ip):
            ip_type = "Multicast"
        else:
            ip_type = "Unicast"
    else:
        ip_scope = "N/A"
            
    # IP Scope
    # Uses regex to categorise IP addresses based on specific patterns
    ip_scope = ""
    if ip_version == "IPv4":
        if re.search(r"^192\.168\.", ip) or \
        re.search(r"^10\.", ip) or \
        re.search(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip):
            ip_scope = "Private"
        elif re.search(r"^127\.", ip):
            ip_scope = "Loopback"
        elif re.search(r"^169\.254\.", ip):
            ip_scope = "Link-local"
        else:
            ip_scope = "Public"

    elif ip_version == "IPv6":
        if ip_type == "Unicast":
            if re.search(r"^::1", ip):
                ip_scope = "Loopback"
            elif re.search(r"^::", ip):
                ip_scope = "Unspecified"
            elif re.search(r"^fe80", ip):
                ip_scope = "Link-local"
            elif re.search(r"^fd|^fc", ip):
                ip_scope = "Private"
            elif re.search(r"^2|^3", ip):
                ip_scope = "Public"
        elif ip_type == "Multicast":
            if re.search(r"^.{3}1", ip):
                ip_scope = "Loopback"
            elif re.search(r"^.{3}2", ip):
                ip_scope = "Link-local"
            elif re.search(r"^.{3}5", ip):
                ip_scope = "Site-local"
            elif re.search(r"^.{3}8", ip):
                ip_scope = "Organisation-local"
            elif re.search(r"^.{3}e", ip):
                ip_scope = "Global"
            else:
                ip_scope = "N/A"
        else:
            ip_scope = "N/A"
    else:
        ip_scope = "N/A"

    if ip_version in ["IPv4", "IPv6"] and ip_scope == "Public":
        
        # Get Geolocation data - return N/A if error or incorrect IP for geolocation mapping
        try:
            response = reader.city(ip)
            ip_country = response.country.name
            ip_city = response.city.name
            ip_lat = response.location.latitude
            ip_lon = response.location.longitude
        except geoip2.errors.AddressNotFoundError:
            ip_country = "N/A"
            ip_city = "N/A"
            ip_lat = "N/A"
            ip_lon = "N/A"
    else:
        ip_country = "N/A"
        ip_city = "N/A"
        ip_lat = "N/A"
        ip_lon = "N/A"


    # Trust - is IP in malicious IP list
    if ip_scope == "Public" and ip_type == "Unicast":
        ip_obj = ipaddress.ip_address(ip)
        if ip in ip_set or any(ip_obj in net for net in networks):
            ip_trust = "Malicious"
        else:
            ip_trust = "Not malicious"
    else:
        ip_trust = "Internal"
        
    # Cache results so that IP details don't get recomputed again for same IP address
    result = (ip_version, ip_type, ip_scope, ip_country, ip_city, ip_lat, ip_lon, ip_trust)
    ip_cache[ip] = result
    return result








def port_details(port, protocol):

    """
    Determines the type and service of a network port.

    Args:
        port (str or int): The port number from a log entry.
        protocol (str): The network protocol (TCP/UDP etc).

    Returns:
        tuple: (port_type, port_service)
               - port_type: classification (Well-Known, Registered, Ephemeral, or N/A)
               - port_service: service name or 'N/A'
    """
    # Handle missing or invalid port values
    if port in ["-", None, ""]:
        return "N/A", "N/A"
    
    # Service lookup only applies to TCP/UDP ports
    if protocol in ["TCP", "UDP"]:

        port = int(port)

        if port <= 1023:
            port_type = "Well-Known"
        elif port <= 49151:
            port_type = "Registered"
        else:
            port_type = "Ephemeral"

        # Uses users local system to get service data
        port_service = get_service(port, protocol.lower())
    else:
        port_type = "N/A" 
        port_service = "N/A"
    
    return port_type, port_service




def get_service(port, protocol):

    """
    Get the service for a port.

    Args:
        port (int): A port number.
        protocol (str): The network protocol (TCP/UDP etc).

    Returns:
        string: (A service name or 'Unknown').
    """

    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "Unknown"
    




def pop_map(logs):

    """
    Extracts geographic coordinates from logs for map visualisation.

    For inbound traffic, the source IP location is used.
    For outbound traffic, the destination IP location is used.

    Args:
        logs (list): List of enriched log dictionaries containing an "extra" field
                     with geolocation and direction data.

    Returns:
        list: A list of dictionaries, each containing:
            - lat (float): Latitude of the IP location
            - lon (float): Longitude of the IP location
            - type (str): Traffic direction ("inbound" or "outbound")

    Notes:
        - Only logs with valid latitude and longitude values are included.
        - Logs with missing or "N/A" location data are ignored.
    """

    map_points = []

    for log in logs:
        extra = log.get("extra", {})
        direction = extra.get("direction")

        # Ensure location data is present
        # Only care about source IP if the connection is inbound i.e. its an external device
        if extra.get("src_ip_lat") not in ["N/A", None] and extra.get("src_ip_lon") not in ["N/A", None] and direction == "Inbound":
            map_points.append({
                "lat": float(extra["src_ip_lat"]),
                "lon": float(extra["src_ip_lon"]),
                "type": "inbound"
            })

        # Ensure location data is present
        # Only care about destination IP if the connection is outbound i.e. its an external device
        elif extra.get("dst_ip_lat") not in ["N/A", None] and extra.get("dst_ip_lon") not in ["N/A", None] and direction == "Outbound":
            map_points.append({
                "lat": float(extra["dst_ip_lat"]),
                "lon": float(extra["dst_ip_lon"]),
                "type": "outbound"
            })
    return map_points



def get_stats(logs):

    """
    Acquires statistics on all logs for data visualisation.

    Args:
        logs (list): List of enriched log dictionaries.

    Returns:
        dictionary: A dictionary containing:
            - log_count (int): Number of logs
            - allow_count (int): Number of allowed connections
            - drop_count (int): Number of dropped connections
            - inbound_count (int): Number of inbound (received) connection attempts
            - outbound_count (int): Number of outbound (sent) connection attempts
            - protocol_labels (list): A list of all unique protocol names
            - protocol_counts (list): A list of counts for unique protocols corresponding to protocol_labels
            - inbound_ip_listcount (dict): A dictionary of the most common inbound ip addresses and their corresponding number of instances
            - outbound_ip_listcount (dict): A dictionary of the most common outbound ip addresses and their corresponding number of instances
            - insights (list): A list of insights (strings)
    """

    log_count = 0
    allow_count = 0
    drop_count = 0
    inbound_count = 0
    outbound_count = 0
    protocols = {}
    inbound_ip_listcount ={}
    outbound_ip_listcount ={}
    country_listcount = {}
    malicious_listcount = {}

    for log in logs:
        log_count += 1

        if log["action"] == "ALLOW":
            allow_count += 1
        if log["action"] == "DROP":
            drop_count += 1

        if log["path"] == "RECEIVE":
            inbound_count += 1
        if log["path"] == "SEND":
            outbound_count += 1
        
        # Get unique protocols + counts for pie chart
        protocol = log["protocol"]

        if protocol not in protocols:
            protocols[protocol] = 1
        else:
            protocols[protocol] += 1
        
        
        if log["path"] == "RECEIVE":

            ip = log["src-ip"]

            # For common inbound IP addresses + their number or appearances
            if ip not in inbound_ip_listcount:
                inbound_ip_listcount[ip] = 1
            else:
                inbound_ip_listcount[ip] += 1
            
            # For common country connections in insight section
            country = log["extra"]["src_ip_country"]

            if country not in country_listcount:
                country_listcount[country] = 1
            else:
                country_listcount[country] += 1

        else:

            ip = log["dst-ip"]

            # For common outbound IP addresses + their number or appearances
            if ip not in outbound_ip_listcount:
                outbound_ip_listcount[ip] = 1
            else:
                outbound_ip_listcount[ip] += 1

        
        

        # For malicious IP alert in insight section
        for trust_key, ip_key in [("src_ip_trust", "src-ip"), ("dst_ip_trust", "dst-ip")]:
            if log["extra"][trust_key] == "Malicious":
                ip = log[ip_key]

                if ip not in malicious_listcount:
                    malicious_listcount[ip] = 1
                else:
                    malicious_listcount[ip] += 1



    # Get most common items from listcounts
    inbound_ip_listcount = dict(
        sorted(inbound_ip_listcount.items(), key=lambda item: item[1], reverse=True)[:5]
    )
    outbound_ip_listcount = dict(
        sorted(outbound_ip_listcount.items(), key=lambda item: item[1], reverse=True)[:5]
    )

    country_listcount = dict(
        sorted(country_listcount.items(), key=lambda item: item[1], reverse=True)[:3]
    )

    malicious_listcount = dict(
        sorted(malicious_listcount.items(), key=lambda item: item[1], reverse=True)
    )

    # Data for protocol pie chart
    protocol_labels = list(protocols.keys())
    protocol_counts = list(protocols.values())

    # Data for malicious alerts in insights
    malicious_count = len(malicious_listcount)
    malicious_list = list(malicious_listcount)
    top_malicious = malicious_list[:5]
    

    # Drop/Allow insight
    insights = []

    if log_count > 0:
        drop_ratio = drop_count / log_count
    else:
        drop_ratio = 0

    if drop_ratio > 0.2:
        insights.append({
            "message": "High number of blocked connections detected",
            "type": "warning"
        })
    else:
        insights.append({
            "message": "Low level of blocked traffic",
            "type": "info"
        })


    # Outbound/Inbound insight
    if outbound_count > inbound_count:
        insights.append({
            "message": "Traffic is primarily outbound",
            "type": "info"
        })
    else:
        insights.append({
            "message": "Significant inbound traffic detected",
            "type": "warning"
        })

    # Country insight
    common_country_list = []
    for key in country_listcount:
        if key and key != "N/A":
            common_country_list.append(key)

    if len(common_country_list) == 0:
        countries = "None"
    elif len(common_country_list) == 1:
        countries = common_country_list[0]
    else:
        countries = ", ".join(common_country_list[:-1]) + " and " + common_country_list[-1]

    if countries == "None":
        insights.append({
            "message": "No inbound connection location data acquired",
            "type": "info"
        })
    else:
        insights.append({
            "message": "Inbound connections originate mainly from " + countries,
            "type": "info"
        })

    # Malicious Ip Alert
    if malicious_count > 0:
        insights.append({
            "message": f"{malicious_count} malicious IP Addresses detected (top: {', '.join(top_malicious)})",
            "type": "alert"
        })

    log_stats = {
        "log_count": log_count,
        "allow_count": allow_count,
        "drop_count": drop_count,
        "inbound_count": inbound_count,
        "outbound_count": outbound_count,
        "protocol_labels": protocol_labels,
        "protocol_counts": protocol_counts,
        "inbound_ip_listcount": inbound_ip_listcount,
        "outbound_ip_listcount": outbound_ip_listcount,
        "insights": insights
    }

    return log_stats




def get_time_data(logs):

    """
    Extracts date/time data from logs for data visualisation.

    Args:
        logs (list): List of enriched log dictionaries containing an "extra" field
                     with date/time data.

    Returns:
        dictionary: A dictionary containing:
            - time_chart_labels (list): A list of dates/times representing the bins that time data will go into
            - time_bin_data (list): List of overall log traffic per bin
            - allow_bin_data (list): List of allowed log traffic per bin
            - drop_bin_data (list): List of dropped log traffic per bin
    """

    # Join date and time into correct format, remove null bytes (\x00), and add action for splitting line chart into allow or drop lines
    times = [
        (
            datetime.strptime((log["date"] + " " + log["time"]).replace("\x00", "").strip(), "%Y-%m-%d %H:%M:%S"), log["action"]
        )
        for log in logs
    ]

    if not times:
        return {"time_bin_data": [], "time_chart_labels": []}

    # Get time range for time chart borders
    min_time = min(t[0] for t in times)
    min_time = min_time.replace(second=0, microsecond=0)
    max_time = max(t[0] for t in times)

    # Put into seconds to be able to do calculations - divide into bins
    seconds = (max_time - min_time).total_seconds()

    if seconds == 0:
        return {
            "time_bin_data": [len(times)],
            "time_chart_labels": [min_time.strftime("%Y-%m-%d %H:%M:%S")]
        }

    # Set a target bin count - uses square root to appropriately flex bin count
    bin_count_target = max(5, min(30, int(math.sqrt(len(logs)))))
    raw_bin = seconds / bin_count_target

    # Round for less precise numbers - better presentation in chart
    bin_seconds = max(1, round(raw_bin / 10) * 10)
    bin_count = max(1, math.ceil(seconds / bin_seconds))

    # Initialise lists with predefined list lengths - for indexing - faster computation than looping multiple times
    times_per_bin = [0] * bin_count
    allow_per_bin = [0] * bin_count
    drop_per_bin = [0] * bin_count

    for t in times:
        dt = t[0]
        index = int((dt - min_time).total_seconds() / bin_seconds)
        if index >= bin_count:
            index = bin_count - 1
        times_per_bin[index] += 1
        if t[1] == "ALLOW":
            allow_per_bin[index] +=1
        if t[1] == "DROP":
            drop_per_bin[index] +=1

    # Set chart labels equal to the bins mid point - more intuitive + better presentation than listing ranges
    time_labels = []
    for i in range(bin_count):
        label_dt = min_time + timedelta(seconds=bin_seconds * (i + 0.5))
        time_labels.append(label_dt.strftime("%H:%M:%S"))

    time_data = {
        "time_bin_data": times_per_bin,
        "allow_bin_data": allow_per_bin,
        "drop_bin_data": drop_per_bin,
        "time_chart_labels": time_labels
    }

    return time_data
            




def configure_logs(logs):

    """
    Decides/Sorts what fields in logs will be visible in the main dict body, and which will be stored in extra

    This dictates what will be displayed in the main html table (which values can be filtered)

    Args:
        logs (list): List of enriched log dictionaries containing an "extra" field
                     with additional data.

    Returns:
        configured_logs (list): A list of reconfigured dictionaries
    """

    visible_fields = [
        "date",
        "time",
        "protocol",
        "action",
        "src-ip",
        "dst-ip",
        "src-port",
        "dst-port",
        "size",
        "path",
        "pid"
    ]

    configured_logs = []

    for log in logs:
        new_log = {}
        new_log["extra"] = {}

        # Go through items in main section of log -> (not in "extra")
        for key, value in log.items():

            if key in visible_fields:
                new_log[key] = value
            elif key != "extra":
                new_log["extra"][key] = value

        # Go through items in "extra" section of log
        for key, value in log["extra"].items():

            if key in visible_fields:
                new_log[key] = value
            else:
                new_log["extra"][key] = value
        
        configured_logs.append(new_log)

    return configured_logs




def validate(logs):

    """
    Validates the values in logs 

    Args:
        logs (list): List of dictionaries.

    Returns:
        str or None:
                - Error message if validation fails, otherwise None.
    """

    i = 0
    error_check = None

    for log in logs:

        i += 1
        for key, value in log.items():

            # Date
            if key == "date" and value != "-":
                if not validate_date(value):
                    error_check = key
                    error_value = value
                    break
            
            # Time
            elif key == "time" and value != "-":
                if not validate_time(value):
                    error_check = key
                    error_value = value
                    break

            # IP
            elif key in ["src-ip", "dst-ip"] and value != "-":
                if not validate_ip(value):
                    error_check = key
                    error_value = value
                    break
            
            # Port
            elif key in ["src-port", "dst-port"] and value != "-":
                if not validate_port(value):
                    error_check = key
                    error_value = value
                    break

            # Size and pid    
            elif key in ["size", "pid"] and value != "-":
                if not validate_int(value):
                    error_check = key
                    error_value = value
                    break

        if error_check:
            break

    if error_check:
        return f"Error in '{error_check}' (value: {error_value}) in log {i}"
    else:
        return None
   


def validate_date(value):

    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except(ValueError, TypeError):
        return False
    
def validate_time(value):
    try:
        datetime.strptime(value, "%H:%M:%S")
        return True
    except(ValueError, TypeError):
        return False
    
def validate_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except(ValueError, TypeError):
        return False

def validate_port(value):
    try:
        port = int(value)
        return 0 <= port <= 65535
    except(ValueError, TypeError):
        return False

def validate_int(value):
    try:
        num = int(value)
        return num >= 0
    except(ValueError, TypeError):
        return False

def validate_action(value):
    try: 
        return value.lower() in ["allow", "drop"]
    except(ValueError, TypeError):
        return False

def validate_path(value):
    try: 
        return value.lower() in ["send", "receive"]
    except(ValueError, TypeError):
        return False
    


