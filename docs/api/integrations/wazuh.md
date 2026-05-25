# Wazuh Integration

## CDB list pull

Wazuh's CDB lists work directly with our CSV feed:

```bash
# /var/ossec/etc/lists/pcap-hunter
# Updated by cron every 15 minutes
*/15 * * * * curl -fsS -H "Authorization: Bearer $FEED_KEY" \
    'http://pcap-hunter.internal:8000/api/v1/iocs.csv?type=ip,domain' \
    | awk -F',' 'NR>1 {print $2":"$4}' \
    > /var/ossec/etc/lists/pcap-hunter
/var/ossec/bin/ossec-control restart
```

Then reference it in a Wazuh rule:
```xml
<rule id="100100" level="10">
  <list field="srcip" lookup="address_match_key">etc/lists/pcap-hunter</list>
  <description>PCAP Hunter flagged source IP</description>
</rule>
```
