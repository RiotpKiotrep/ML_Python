import requests
import urllib3
import time
import xml.etree.ElementTree as ET
import pandas as pd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_job_id(firewall_ip, api_key):
    url = f"https://{firewall_ip}/api/?type=log&log-type=traffic&key={api_key}"
    response = requests.get(url, verify=False)
    root = ET.fromstring(response.content)
    job_id = root.find(".//job").text
    return job_id

def get_logs(job_id, firewall_ip, api_key):
    url = f"https://{firewall_ip}/api/?type=log&action=get&job-id={job_id}&key={api_key}"
    cols_to_keep = ['elapsed', 'proto', 'pkts_sent', 'pkts_received', 'bytes_sent', 'bytes_received', 'src']

    while True:
        response = requests.get(url, verify=False)
        root = ET.fromstring(response.content)
        status = root.get("status")
        if status == "success":
            log_entries = root.findall(".//entry")
            if log_entries:
                logs = []
                for log_entry in log_entries:
                    entry_data = {child.tag: child.text for child in log_entry}
                    entry_data.update(log_entry.attrib)
                    logs.append(entry_data)
                    #log = ET.tostring(log_entry, encoding='utf-8').decode('utf-8')
                    #logs.append(log)
            else:
                print("Czekanie na logi")

            log_df = pd.DataFrame(logs)
            
            log_df = log_df[cols_to_keep]
            return log_df
        else:
            print(f"Unexpected status: {status}")
        time.sleep(1)


def block_ip(ip):
    url = "https://10.74.1.18/api/?type=config&action=set&xpath=/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules&key=LUFRPT10TFJITGcwU3RoRDlLZ1pTOXhFWVFxWHhEN289Um0vWSs3b0toUHRsZnl4YUh0cUwzZmJXdTNibHEzWjMzNjA2aVd3aWh5SlRJSHR5aWxZYkNzQ2VwRW1kb2dRRw=="
    headers = {
        'Content-Type': 'application/xml'
    }
    payload = f"""
    <entry name="Block-IP">
        <from>
            <member>untrust</member>
        </from>
        <to>
            <member>trust</member>
        </to>
        <source>
            <member>{ip}</member>
        </source>
        <destination>
            <member>any</member>
        </destination>
        <application>
            <member>any</member>
        </application>
        <service>
            <member>application-default</member>
        </service>
        <action>deny</action>
    </entry>
    """
    response = requests.post(url, data=payload, headers=headers, verify=False)
    if response.status_code == 200:
        print(f"Adres {ip} zablokowany")
    else:
        print("Błąd")