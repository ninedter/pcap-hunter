# Wazuh 整合

## CDB 清單拉取

Wazuh 的 CDB 清單可直接使用我們的 CSV 摘要：

```bash
# /var/ossec/etc/lists/pcap-hunter
# 每 15 分鐘由 cron 更新
*/15 * * * * curl -fsS -H "Authorization: Bearer $FEED_KEY" \
    'http://pcap-hunter.internal:8000/api/v1/iocs.csv?type=ip,domain' \
    | awk -F',' 'NR>1 {print $2":"$4}' \
    > /var/ossec/etc/lists/pcap-hunter
/var/ossec/bin/ossec-control restart
```

接著在 Wazuh 規則中引用：
```xml
<rule id="100100" level="10">
  <list field="srcip" lookup="address_match_key">etc/lists/pcap-hunter</list>
  <description>PCAP Hunter 標記的來源 IP</description>
</rule>
```
