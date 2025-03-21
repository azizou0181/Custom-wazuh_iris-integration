#!/var/ossec/framework/python/bin/python3
# custom-wazuh_iris.py
# Custom Wazuh integration script to send alerts to DFIR-IRIS

import requests
import json
import logging
import sys
import time

# Configure logging
logging.basicConfig(filename='/var/ossec/logs/integrations.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def get_alerts_from_wazuh_indexer(wazuh_indexer_url, api_user, api_password):
    query = {
        "query": {
            "bool": {
                "must": [
                    # Filter for alerts with a rule level greater than 7
                    {"range": {"rule_level": {"gt": 7}}},
                    
                    # Filter for alerts that occurred within the last 24 hours
                    {"range": {"timestamp": {"gte": "now-1d", "lte": "now"}}}
                ]
            }
        },
        "size": 50,  
        "sort": [{"timestamp": {"order": "desc"}}]
    }

    try:
        response = requests.get(
            f"{wazuh_indexer_url}/wazuh-alerts-*/_search",
            auth=(api_user, api_password),
            headers={"Content-Type": "application/json"},
            json=query,
            verify=False
        )
        response.raise_for_status()
        response_json = response.json()

        alerts = response_json.get("hits", {}).get("hits", [])
        if not alerts:
            logging.info("No alerts found with rule_level >= 7.")
            return None

        return [alert["_source"] for alert in alerts]

    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying Wazuh Indexer: {e}")
        return None

def format_alert_details(alert_json):
    formatted_alerts = []

    for alert in (alert_json if isinstance(alert_json, list) else [alert_json]):
        message = alert.get("message", "{}")
        try:
            message_json = json.loads(message) if isinstance(message, str) else message
        except json.JSONDecodeError:
            logging.error("Failed to decode 'message' field as JSON.")
            formatted_alerts.append("Invalid message format")
            continue

        rule = message_json.get("rule", {})
        agent = message_json.get("agent", {})

        mitre = rule.get("mitre", {})
        details = [
            f"Rule ID: {rule.get('id', 'N/A')}",
            f"Rule Level: {rule.get('level', 'N/A')}",
            f"Rule Description: {rule.get('description', 'N/A')}",
            f"Agent ID: {agent.get('id', 'N/A')}",
            f"Agent Name: {agent.get('name', 'N/A')}",
            f"MITRE IDs: {', '.join(mitre.get('id', ['N/A']))}",
            f"MITRE Tactics: {', '.join(mitre.get('tactic', ['N/A']))}",
            f"MITRE Techniques: {', '.join(mitre.get('technique', ['N/A']))}",
            f"Location: {alert.get('location', 'N/A')}",
            f"Full Log: {alert.get('full_log', 'N/A')}",
          
            # Uncomment and modify the following lines to include additional fields as needed for your environment.
            # For example, you might want to add fields like Destination IP, Source Hash, etc., depending on your log data.
          
            #f"Destination IP: {alert.get('dst_ip', 'N/A')}",   
            #f"Destination Port: {alert.get('dst_port', 'N/A')}",
            #f"Source Hash: {alert.get('src_hash', 'N/A')}",
            #f"Query Name: {alert.get('query_name', 'N/A')}"
        ]

        formatted_alerts.append('\n'.join(details))

    return '\n\n'.join(formatted_alerts)

def main():
    logging.debug(f"Received arguments: {sys.argv}")
    if len(sys.argv) < 4:
        logging.error("Insufficient arguments provided. Exiting.")
        sys.exit(1)

    api_key, hook_url = sys.argv[2], sys.argv[3]

    wazuh_indexer_url = "https://<IP ADDRESS>:9200"  #Replace with actual Wazuh Indexer IP address 
    api_user, api_password = "admin", "password"     #Replace with Wazuh credentials in order to access the Wazuh Indexer API

    processed_alerts = set()

    while True:
        logging.info("Fetching new alerts from Wazuh Indexer...")
        alerts = get_alerts_from_wazuh_indexer(wazuh_indexer_url, api_user, api_password)

        if alerts:
            for alert_json in alerts:
                alert_id = alert_json.get("id", "Unknown ID")
                if alert_id in processed_alerts:
                    continue

                processed_alerts.add(alert_id)
                alert_details = format_alert_details(alert_json)

                message = alert_json.get("message", "{}")
                try:
                    message = json.loads(message) if isinstance(message, str) else message
                except json.JSONDecodeError:
                    logging.error("Failed to parse 'message' as JSON.")
                    message = {}

                alert_level = message.get("rule", {}).get("level", 0)
                severity = (
                    2 if alert_level < 5 else
                    3 if alert_level < 7 else
                    4 if alert_level < 10 else
                    5 if alert_level < 13 else
                    6
                )

                payload = json.dumps({
                    "alert_title": message.get("rule", {}).get('description', 'N/A'),
                    "alert_description": alert_details,
                    "alert_source": "Wazuh",
                    "alert_source_ref": alert_id,
                    "alert_source_link": "https://<IP ADDRESS>/app/wz-home",  # Replace with actual Wazuh dashboard IP address
                    "alert_severity_id": severity,
                    "alert_status_id": 2,
                    "alert_source_event_time": alert_json.get("timestamp", "Unknown Timestamp"),
                    "alert_note": "",
                    "alert_tags": f"wazuh,{alert_json.get('agent', {}).get('name', 'N/A')}",
                    "alert_customer_id": 1,  # '1' for default 'IrisInitialClient'
                    "alert_source_content": alert_json
                })

                try:
                    response = requests.post(
                        hook_url, data=payload, headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}, verify=False
                    )
                    if response.status_code in [200, 201, 202, 204]:
                        logging.info(f"Sent alert {alert_id} to IRIS. Response: {response.status_code}")
                    else:
                        logging.error(f"Failed to send alert {alert_id} to IRIS. Response: {response.status_code}")
                except Exception as e:
                    logging.error(f"Failed to send alert {alert_id} to IRIS: {e}")

        logging.info("Sleeping for 30 seconds before next check...")
        time.sleep(30)

if __name__ == "__main__":
    main()
