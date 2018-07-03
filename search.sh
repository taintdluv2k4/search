#!/bin/bash

SPLUNK_HOME=/opt/splunk
ADMUSR=admin
read -p "Enter Admin password: " ADMPASS

echo "########################################################################################################################################"
echo "Firewall Rule Activiy"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'network communicate | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search '| table _time,host,sourcetype,action,dvc,rule,transport,src,src_port,dest,dest_port,vendor_product | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search '| inputlookup append=t | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Network Traffic Activity"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype=cisco* | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'network communicate | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search '| fields sourcetype, action, dvc, rule, transport, src, dest | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Prohibited Services"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*Services" | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*Service" | table dest, StartMode | table dest, StartMode | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*:LocalProcess" | table dest, process | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'listening port | table dest,dest_port,transport | table dest,dest_port,transport | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search '| inputlookup append=T | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Default Account Access"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype=cisco* | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'authentication | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'root or admin or administrator or ubuntu or ec2-user or fedora or openvpnas or sguser | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sudo | fields sourcetype, action, app, src, src_user, dest, user | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Insecure Authentication Attempts"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'authentication | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'cleartext insecure | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'authentication insecure | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sudo | tags outputfield=tag | table _time,host,action,app,src,src_user,dest,user,tag | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'source="/var/log/authlog" | rex "Last\s+message\s+repeated\s+(?<repeatsNoContext>\d+)\s+times." | fillnull value=0 repeatsNoContext | autoregress repeatsNoContext AS repeatsForMe | eval myCount= 1 + repeatsForMe | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*:Service" | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*:Service" | table dest, StartMode | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "PCI System Inventory"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*:LocalProcesses" | table dest, process | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'listening port | table dest,dest_port,transport | table dest,dest_port,transport | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*Services" | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*Services" | table dest, StartMode | table dest, StartMode | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*:LocalProcess" | table dest, process | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'listening port | table dest,dest_port,transport | table dest,dest_port,transport | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'snort and attack | search misconfiguration | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'snort and attack | search misconfiguration | tags outputfield=tag | table _time,host,sourcetype,dvc,ids_type,category,signature,severity,src,dest,tag,vendor_product | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Weak Encrypted Communication"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'misconfiguration wireless | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'snort and attack | search misconfiguration wireless | tags outputfield=tag | table_time,host,sourcetype,dvc,ids_type,category,signature,severity,src,dest,<br>tag,vendor_product | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Wireless Network Misconfigurations"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'snort and attack | search pii ids attack | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'snort and attack | search pii ids attack | table src, dest, dvc, signature | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Credit Card Data Found"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'malware attack | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Endpoint Product Deployment"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'malware operations | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'malware operations | table dest, product_version, vendor | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search '| inputlookup append=T clamav and update* | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Anomalous System Uptime"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'malware attack | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Patch Service Status report"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'malware operations | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'malware operations | table signature_version,dest,vendor | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search '| inputlookup append=T | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'clamav and update* | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "System Patch Status"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'uptime os performance | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'uptime os performance | fields dest, uptime | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "PCI Command History"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*:Service" | stats count by dest | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*:Service" | table, dest | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search '| inputlookup append=T | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "PCI Resource Access"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'update status | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'update status | table signature_id, signature, status | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "PCI Asset Logging"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*Services" | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'authentication | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Endpoint Changes"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*Services" | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'endpoint change | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'endpoint change | fillnull value=unknown action, dest, object, object_category, object_path, status, user | table action,dest,object,object_category,object_path,status,user | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Privileged User Activity"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*Services" | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sudo | table _time, host, action, app, src, src_user, dest, user | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'privileged | table event_id host sourcetype src_user user eventtype | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "System Time Synchronization"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'time synchronizeos performance | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Rogue Wireless Access Point Protection"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*Services" | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'rogue wireless ids attack | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'rogue wireless pci ids attack | table _time,host,sourcetype,dvc,ids_type,category,signature,severity,src,dest,tag,vendor_product | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'snort and attack | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "Vulnerability Scan Details"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'sourcetype="*Services" | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'vulnerability report | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'clamav and vuln*| table _time,dest,category,signature,cve,bugtraq,cert,msft,mskb,xref,severity,cvss,os vendor_product | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5

echo ""
echo "########################################################################################################################################"
echo "IDS/IPS Alert Activity"
echo "########################################################################################################################################"
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'ids attack or snort and attack | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
ALRT=$(${SPLUNK_HOME}/bin/splunk search 'snort and attack | tags outputfield=tag | table _time, host, sourcetype, dvc, ids_type, category, signature, severity, src, dest, tag, vendor_product | sort -count' -earliest_time '-24h' -auth ${ADMUSR}:${ADMPASS})
if [ ${ALRT} -gt 5 ]; then echo ${ALRTLST}; else echo "No alerts"; fi
sleep 5
