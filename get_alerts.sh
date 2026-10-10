#!/bin/bash
docker compose -f ~/wazuh-docker/single-node/docker-compose.yml exec -T wazuh.manager cat /var/ossec/logs/alerts/alerts.json > ~/soc-ai/alerts.json
wc -l ~/soc-ai/alerts.json
