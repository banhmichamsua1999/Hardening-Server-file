from datetime import datetime
import subprocess
import json

pcidss = ["auditd", "filebeat", "teleport", "wazuh-agent"]
result = {}
result["date"] = str(datetime.now())
result["type"] = "pci-healthcheck"
result["pcidss"] = {}
result["services"] = []

try:
    for i in subprocess.check_output("systemctl -t service | grep .service", shell=True).decode("utf-8").strip().split("\n"):
        result["services"].append({
            "service": i.strip().split()[0],
            "status": i.strip().split()[3]
        })
    for service in pcidss:
        result["pcidss"][service] = {
            "status": subprocess.check_output("systemctl -t service | grep {}".format(service), shell=True).decode("utf-8").strip().split()[3]
        }
    result["pcidss"]["teleport"]["version"] = subprocess.check_output("/usr/local/bin/teleport version", shell=True).decode("utf-8").strip()
    result["pcidss"]["filebeat"]["version"] = subprocess.check_output("/usr/bin/filebeat version", shell=True).decode("utf-8").strip()
    if "Ubuntu" in subprocess.check_output("hostnamectl", shell=True).decode("utf-8"):
        result["pcidss"]["wazuh-agent"]["version"] = subprocess.check_output("dpkg --list wazuh-agent | grep wazuh-agent", shell=True).decode("utf-8").strip().split()[2]
        result["pcidss"]["auditd"]["version"] = subprocess.check_output("dpkg --list auditd | grep auditd", shell=True).decode("utf-8").strip().split()[2]
    else:
        result["pcidss"]["wazuh-agent"]["version"] = subprocess.check_output("yum list wazuh-agent | grep wazuh-agent", shell=True).decode("utf-8").strip().split()[1]
        result["pcidss"]["auditd"]["version"] = subprocess.check_output("yum list audit | grep audit", shell=True).decode("utf-8").strip().split()[1]
    result["pcidss"]["clamav"] = {
        "status": None,
        "version": subprocess.check_output("/usr/local/bin/clamscan -V", shell=True).decode("utf-8").strip()
    }
    result["error"] = None
except Exception as e:
    result["error"] = str(e)

# print(str(json.dumps(result)))
f = open("/var/log/syslog", "a")
f.write(str(json.dumps(result)) + "\n")
f.close()
