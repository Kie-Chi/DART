#!/bin/bash

# Define PCAP path and output directory
PCAP_FILE="raw.pcap"
OUT_DIR="tshark_output"

mkdir -p "$OUT_DIR"

# Define Resolver mapping
declare -A RESOLVERS
RESOLVERS=(
    ["bind"]="10.10.66.3"
    ["bind-new"]="10.10.66.4"
    ["unbound"]="10.10.66.5"
    ["unbound-new"]="10.10.66.6"
)

echo "Starting PCAP parsing and exporting to JSON..."

for name in "${!RESOLVERS[@]}"; do
    ip="${RESOLVERS[$name]}"
    out_file="$OUT_DIR/responses_${name}.json"

    echo "Filtering DNS packets for responses to $name ($ip)..."

    tshark -r "$PCAP_FILE" \
       -Y "dns.flags.response == 1 && ip.dst == $ip" \
       -T json \
         > "$out_file"

    echo "Exported: $out_file"
done

echo "All exports completed!"