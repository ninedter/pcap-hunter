# Splunk 整合

## 方案 A — REST API 模組化輸入

```ini
# $SPLUNK_HOME/etc/apps/pcap_hunter/local/inputs.conf
[rest://pcap_iocs]
endpoint = http://pcap-hunter.internal:8000/api/v1/iocs.json
http_header_propagation = true
custom_headers = Authorization=Bearer $FEED_KEY
polling_interval = 900
sourcetype = pcap_hunter:iocs
index = threat_intel
```

## 方案 B — 透過腳本輸入拉取 Lookup CSV

```bash
# $SPLUNK_HOME/etc/apps/pcap_hunter/bin/fetch_iocs.sh
#!/usr/bin/env bash
curl -fsS -H "Authorization: Bearer $FEED_KEY" \
    "http://pcap-hunter.internal:8000/api/v1/iocs.csv" \
    > "$SPLUNK_HOME/etc/apps/pcap_hunter/lookups/pcap_iocs.csv"
```

透過 `inputs.conf` 排程：
```ini
[script://./bin/fetch_iocs.sh]
interval = 900
```
