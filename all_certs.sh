export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
#!/bin/bash

# Redirect all stdout and stderr to a debug log
exec >> /tmp/cert_debug.log 2>&1

# Debugging Info
echo "============================================="
echo "Running all_certs.sh at $(date)"
echo "Current PATH: $PATH"
echo "============================================="

ALL_CERTS_LOG="$HOME/all_certs.log"
JSON_DIR="$HOME/cert_json_logs"
ARCHIVE_DIR="$HOME/cert_json_logs_archive"
DUCKDB_PATH="$HOME/certs.duckdb"

# Ensure JSON log and archive directories exist
mkdir -p "$JSON_DIR"
mkdir -p "$ARCHIVE_DIR"

LAST_HOUR=$(date -v-1H "+%Y%m%d_%H")
CURRENT_HOUR=$(date "+%Y%m%d_%H")

# Archive previous hour's logs
if ls "$JSON_DIR"/${LAST_HOUR}*.json 1> /dev/null 2>&1; then
  ARCHIVE_FILE="$ARCHIVE_DIR/cert_logs_$LAST_HOUR.tar.gz"
  tar -czf "$ARCHIVE_FILE" "$JSON_DIR"/${LAST_HOUR}*.json && rm "$JSON_DIR"/${LAST_HOUR}*.json
  echo "[$(date "+%Y-%m-%d %H:%M:%S")] Archived logs to $ARCHIVE_FILE"
fi

# Remove archives older than 14 days
find "$ARCHIVE_DIR" -type f -name "*.tar.gz" -mtime +14 -exec rm {} \;
echo "[$(date "+%Y-%m-%d %H:%M:%S")] Deleted archives older than 14 days"

while true; do
  TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
  FILE_TIMESTAMP=$(date "+%Y%m%d_%H%M")
  JSON_FILE="$JSON_DIR/$FILE_TIMESTAMP.json"

  # Initialize JSON file if it doesn't exist
  if [[ ! -f "$JSON_FILE" ]]; then
    echo "[]" > "$JSON_FILE"
  fi

  echo "[$TIMESTAMP] Checking active HTTPS connections..."

  # Extract only destination IP addresses from active HTTPS connections
  lsof -i TCP:443 -nP 2>/dev/null | awk '{print $9}' | grep -Eo '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(:[0-9]+)?$' | awk -F':' '{print $1}' | sort -u | while read -r IP; do
    echo "Processing IP: $IP"

    # Extract SSL certificate details
    CERT_INFO=$(echo | openssl s_client -connect "$IP":443 -servername "$IP" -verify_quiet 2>/dev/null | openssl x509 -noout -subject -issuer -fingerprint -sha256 2>/dev/null)

    if [[ -n "$CERT_INFO" ]]; then
      SUBJECT=$(echo "$CERT_INFO" | grep "subject=" | cut -d'=' -f2-)
      ISSUER=$(echo "$CERT_INFO" | grep "issuer=" | cut -d'=' -f2-)
      FINGERPRINT=$(echo "$CERT_INFO" | grep "SHA256 Fingerprint" | awk '{print $NF}')

      # Extract cert expiry date
      RAW_EXPIRES=$(echo | openssl s_client -connect "$IP":443 -servername "$IP" -verify_quiet 2>/dev/null | \
                    openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

      # Convert to YYYY-MM-DD HH:MM:SS format
      EXPIRES=$(date -j -f "%b %d %T %Y %Z" "$RAW_EXPIRES" +"%Y-%m-%d %H:%M:%S" 2>/dev/null)

      JSON_ENTRY=$(/opt/homebrew/bin/jq -n --arg timestamp "$TIMESTAMP" \
                         --arg ip "$IP" \
                         --arg subject "$SUBJECT" \
                         --arg issuer "$ISSUER" \
                         --arg fingerprint "$FINGERPRINT" \
                         --arg expires "$EXPIRES" \
                         '{timestamp: $timestamp, ip: $ip, subject: $subject, issuer: $issuer, fingerprint: $fingerprint, expires: $expires}')

      TMP_FILE="$JSON_FILE.tmp"
      /opt/homebrew/bin/jq ". + [$JSON_ENTRY]" "$JSON_FILE" > "$TMP_FILE" && mv "$TMP_FILE" "$JSON_FILE"

      echo "$TIMESTAMP - $IP" | tee -a "$ALL_CERTS_LOG"
      echo "$CERT_INFO" | tee -a "$ALL_CERTS_LOG"
      echo "Expires On: $EXPIRES" | tee -a "$ALL_CERTS_LOG"
      echo "----------------------------" | tee -a "$ALL_CERTS_LOG"

      # Insert into DuckDB
      /opt/homebrew/bin/duckdb "$DUCKDB_PATH" <<EOF
CREATE TABLE IF NOT EXISTS certs (
  timestamp TEXT,
  ip TEXT,
  subject TEXT,
  issuer TEXT,
  fingerprint TEXT,
  expires TEXT
);
INSERT INTO certs (timestamp, ip, subject, issuer, fingerprint, expires)
VALUES (
  '$TIMESTAMP',
  '$IP',
  '$(echo "$SUBJECT" | sed "s/'/''/g")',
  '$(echo "$ISSUER" | sed "s/'/''/g")',
  '$FINGERPRINT',
  '$EXPIRES'
);
EOF

    else
      echo "[$TIMESTAMP] ❌ Failed to retrieve certificate for $IP" >> "$HOME/tmp/cert_error.log"
    fi
  done

  echo "[$TIMESTAMP] Sleeping for 60 seconds..."
  sleep 60
done