# Custom-wazuh_iris-integration
This script is a modified version of the [integration script discussed in Wazuh's blog](https://wazuh.com/blog/enhancing-incident-response-with-wazuh-and-dfir-iris-integration/)
 post on enhancing incident response with Wazuh and DFIR-IRIS integration. The original script fetched alerts from the `alerts.json` file in the Wazuh Manager. However, I have updated it to fetch alerts directly from the Wazuh Indexer API, This modification ensures that alerts are retrieved in their final form after normalization, extraction, and any modifications, providing a cleaner and more structured data set for further analysis or integration.


The modified script queries the Wazuh Indexer to retrieve alerts based on certain criteria, such as rule level and timestamp, and then formats these alerts with additional details like rule descriptions, MITRE tactics, agent information, and more. It then forwards these alerts to DFIR-IRIS for enhanced incident response.




## Installation and Setup

1. Clone the Repository
To get started, clone the repository to your system:

```bash
git clone https://github.com/azizou0181/Custom-wazuh_iris-integration.git
```
2. After cloning navigate to the script's directory and open it:

```bash
cd Custom-wazuh_iris-integration
nano custom-wazuh_iris.py

```
3. Modify the Script

make necessary changes as instructed in the comments:
- Adding Custom Fields:
```bash
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
            
            # Add your custom fields here
            # For example:
            # f"Destination IP: {alert.get('dst_ip', 'N/A')}",
            # f"Destination Port: {alert.get('dst_port', 'N/A')}",
            # f"Source Hash: {alert.get('src_hash', 'N/A')}",
            # f"Query Name: {alert.get('query_name', 'N/A')}"
        ]

        formatted_alerts.append('\n'.join(details))

    return '\n\n'.join(formatted_alerts)

```
You can customize this section to include as many fields as needed. For example, if you're using Graylog normalization, you can add fields like Destination IP, Source Hash, or others as they become available in your environment.

- Update Wazuh Indexer Details:
Make sure to replace the placeholder values for the Wazuh Indexer URL and credentials with the correct details in these sections:


```bash
wazuh_indexer_url = "https://<IP ADDRESS>:9200"  # Replace with actual Wazuh Indexer IP address
api_user, api_password = "admin", "password"     # Replace with Wazuh credentials to access the Wazuh Indexer API

```

- Update the Payload Section:
The script sends the extracted alerts to IRIS in a specific format. Ensure you update the following details for your setup:
```bash
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

```
Make sure to replace the placeholder <IP ADDRESS> with the correct IP address of your Wazuh dashboard.

4. Update the `ossec.conf` File
Append the following configuration to the `/var/ossec/etc/ossec.conf` file to enable the integration with DFIR-IRIS:
 ```bash
 <ossec_config>
  <!-- IRIS integration -->
  <integration>
    <name>custom-wazuh_iris.py</name>
    <hook_url>https://<IRIS_IP_ADDRESS>/alerts/add</hook_url>
    <api_key><IRIS_API_KEY></api_key><!-- Replace with your IRIS API key -->
    <alert_format>json</alert_format>
  </integration>
</ossec_config>

 ```
- Replace <IRIS_IP_ADDRESS> with the IP address of the DFIR-IRIS server. Ensure to include the port number if DFIR-IRIS is not listening on the default port 443. For example:

https://192.168.1.2/alerts/add (if DFIR-IRIS is listening on port 443)
https://192.168.1.2:8000/alerts/add (if DFIR-IRIS is listening on port 8000)
- Replace <IRIS_API_KEY> with the API key that you retrieved from the DFIR-IRIS web console.

5. Restart Wazuh Manager:
```bash
systemctl restart wazuh-manager
 ```
