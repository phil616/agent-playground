#!/usr/bin/env bash
# Compare a local DNS resolver against a reference resolver across common and advanced RR types.
# Usage: bash dns-test.sh [local_dns_ip] [port] [reference_dns_ip]
# Example: bash dns-test.sh 127.0.0.1 53 1.1.1.1
# Requirements: bash, dig (dnsutils), awk, sed, grep, sort.
set -uo pipefail

LOCAL_DNS="${1:-127.0.0.1}"
LOCAL_PORT="${2:-53}"
REFERENCE_DNS="${3:-1.1.1.1}"
REPORT_DIR="${REPORT_DIR:-./dns-audit-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$REPORT_DIR"
command -v dig >/dev/null || { echo 'Error: dig is missing. Install: sudo apt install dnsutils'; exit 2; }

# DNS test cases: category | qname | RR type | extra check | strict fixture
# TYPE64/TYPE65 work with both new and older dig versions.
CASES=$(cat <<'CASES_EOF'
Basic IPv4|google.com|A|-|no
Basic IPv6|google.com|AAAA|-|no
Mail MX|google.com|MX|-|no
Mail TXT|google.com|TXT|-|no
Domain NS|cloudflare.com|NS|-|no
Domain SOA|cloudflare.com|SOA|-|no
Demo CNAME|cname.example.isitdns.net|CNAME|-|yes
Demo long TXT|long.example.isitdns.net|TXT|-|yes
Email DMARC|_dmarc.google.com|TXT|-|no
Certificate CAA|caa.example.isitdns.net|CAA|-|yes
Service SRV|_xmpp-server._tcp.example.isitdns.net|SRV|-|yes
XMPP SRV|_xmpp-client._tcp.jabber.org|SRV|-|no
SIP NAPTR|sip2sip.info|NAPTR|-|no
SSH fingerprint|sshfp.example.isitdns.net|SSHFP|-|yes
SSH fingerprint Debian|salsa.debian.org|SSHFP|-|no
DANE TLSA demo|_443._tcp.tlsa.example.isitdns.net|TLSA|-|yes
DANE TLSA Proton|_25._tcp.mail.protonmail.ch|TLSA|-|no
DANE TLSA mailbox.org|_25._tcp.mx4.mailbox.org|TLSA|-|no
HTTPS demo TYPE65|svcb.example.isitdns.net|TYPE65|-|yes
SVCB discovery TYPE64|_dns.one.one.one.one|TYPE64|-|no
HTTPS Cloudflare ECH|cloudflare.com|TYPE65|ech|no
HTTPS Cloudflare crypto|crypto.cloudflare.com|TYPE65|ech|no
HTTPS Cloudflare DNS|cloudflare-dns.com|TYPE65|ech|no
HTTPS Google|google.com|TYPE65|ech|no
HTTPS Google www|www.google.com|TYPE65|ech|no
HTTPS GitHub|github.com|TYPE65|ech|no
DNSSEC DNSKEY|cloudflare.com|DNSKEY|dnssec|no
DNSSEC DS|cloudflare.com|DS|dnssec|no
DNSSEC signed answer|cloudflare.com|A|rrsig|no
CA signed DNSKEY|isitdns.net|DNSKEY|dnssec|no
CA signed DS|isitdns.net|DS|dnssec|no
CA signed CAA|isitdns.net|CAA|dnssec|no
CASES_EOF
)

query() {
    local server="$1" port="$2" name="$3" qtype="$4" extra="$5" destination="$6"
    local -a opts=(+time=3 +tries=1 +bufsize=1232 +noall +comments +answer +stats)
    [[ "$extra" == dnssec || "$extra" == rrsig ]] && opts+=(+dnssec)
    dig "@$server" -p "$port" "$name" "$qtype" "${opts[@]}" >"$destination" 2>&1
}

rcode() {
    sed -n 's/.*status: \([A-Z0-9]*\),.*/\1/p' "$1" | head -n 1
}

rr_count() {
    local file="$1" type="$2"
    awk -v q="$type" '
        BEGIN { if (q == "TYPE65") q = "HTTPS"; if (q == "TYPE64") q = "SVCB"; n=0 }
        /^[;]/ {next}
        NF >= 5 && ($4 == q || (q == "HTTPS" && $4 == "TYPE65") || (q == "SVCB" && $4 == "TYPE64")) {n++}
        END {print n}
    ' "$file"
}

# Strip owner / TTL / class / record-type fields, then sort answer RDATA.
rr_data() {
    local file="$1" type="$2"
    awk -v q="$type" '
        BEGIN { if (q == "TYPE65") q = "HTTPS"; if (q == "TYPE64") q = "SVCB" }
        /^[;]/ {next}
        NF >= 5 && ($4 == q || (q == "HTTPS" && $4 == "TYPE65") || (q == "SVCB" && $4 == "TYPE64")) {
           text=""; for (i=5; i<=NF; i++) text=text (i==5?"":" ") $i;
           print tolower($1) " " text
        }
    ' "$file" | LC_ALL=C sort
}

flag_present() { grep -Eiq "^;; flags:.*[ ;]$2[ ;]" "$1"; }
has_ech() { grep -Eiq '(^|[[:space:]])ech=' "$1"; }

printf 'DNS forwarding audit - %s\n' "$(date -Is)"
printf 'Local: %s:%s | Reference: %s:53\n' "$LOCAL_DNS" "$LOCAL_PORT" "$REFERENCE_DNS"
printf 'Detailed responses: %s\n\n' "$REPORT_DIR"
printf '%-5s %-27s %-37s %-8s %-9s %-9s %s\n' 'No.' 'Test' 'QNAME' 'TYPE' 'Local' 'Ref' 'Result'

pass=0; fail=0; warn=0; skip=0; idx=0
while IFS='|' read -r title name qtype extra strict; do
    [[ -n "$title" ]] || continue
    ((idx+=1))
    local_file="$REPORT_DIR/$(printf '%02d' "$idx")-local.txt"
    ref_file="$REPORT_DIR/$(printf '%02d' "$idx")-reference.txt"
    query "$LOCAL_DNS" "$LOCAL_PORT" "$name" "$qtype" "$extra" "$local_file" || true
    query "$REFERENCE_DNS" 53 "$name" "$qtype" "$extra" "$ref_file" || true
    local_status="$(rcode "$local_file")"; ref_status="$(rcode "$ref_file")"
    local_count="$(rr_count "$local_file" "$qtype")"; ref_count="$(rr_count "$ref_file" "$qtype")"
    result='PASS'; note=''
    if [[ -z "$local_status" ]]; then
        result='FAIL'; note='Local resolver timeout or no valid response'
    elif [[ -z "$ref_status" ]]; then
        result='SKIP'; note='Reference resolver unavailable; no reliable baseline'
    elif [[ "$local_status" != "$ref_status" ]]; then
        if [[ "$name" == dnssec-failed.org ]]; then
            result='WARN'; note='DNSSEC validation behavior differs'
        else
            result='FAIL'; note="Response status mismatch ($local_status vs $ref_status)"
        fi
    elif [[ "$ref_status" == NOERROR ]]; then
        if ((ref_count > 0 && local_count == 0)); then
            result='FAIL'; note='Reference returned requested RR type; local DNS did not'
        elif ((ref_count == 0)); then
            result='SKIP'; note='Reference has no requested RR; cannot test a positive answer'
        elif [[ "$extra" == ech ]] && has_ech "$ref_file" && ! has_ech "$local_file"; then
            result='FAIL'; note='Reference has ech= but local DNS omitted it'
        elif [[ "$extra" == rrsig ]] && grep -Eq '[[:space:]]RRSIG[[:space:]]' "$ref_file" && ! grep -Eq '[[:space:]]RRSIG[[:space:]]' "$local_file"; then
            result='FAIL'; note='Reference sent an RRSIG but local DNS omitted it'
        elif [[ "$strict" == yes ]] && [[ "$(rr_data "$local_file" "$qtype")" != "$(rr_data "$ref_file" "$qtype")" ]]; then
            result='WARN'; note='Fixture answer data differs; inspect raw output (cache/stale data possible)'
        elif [[ "$qtype" == TXT || "$qtype" == MX || "$qtype" == CAA ]] && ((local_count != ref_count)); then
            result='WARN'; note='Answer RR counts differ; inspect raw output (cache or regional variation possible)'
        fi
    fi
    case "$result" in
        PASS) ((pass+=1));; FAIL) ((fail+=1));; WARN) ((warn+=1));; SKIP) ((skip+=1));;
    esac
    printf '%-5s %-27.27s %-37.37s %-8s %-9s %-9s %s\n' "$idx" "$title" "$name" "$qtype" "${local_status:--}/$local_count" "${ref_status:--}/$ref_count" "$result"
    if [[ -n "$note" ]]; then printf '      -> %s\n' "$note"; fi
done <<< "$CASES"

printf '\n--- DNSSEC negative control ---\n'
broken_local="$REPORT_DIR/dnssec-broken-local.txt"
broken_ref="$REPORT_DIR/dnssec-broken-reference.txt"
query "$LOCAL_DNS" "$LOCAL_PORT" dnssec-failed.org A dnssec "$broken_local" || true
query "$REFERENCE_DNS" 53 dnssec-failed.org A dnssec "$broken_ref" || true
printf 'dnssec-failed.org: local=%s, reference=%s (a validating resolver should normally return SERVFAIL)\n' "$(rcode "$broken_local")" "$(rcode "$broken_ref")"
if [[ "$(rcode "$broken_ref")" == SERVFAIL && "$(rcode "$broken_local")" == NOERROR ]]; then
    printf 'WARNING: local resolver accepted a deliberately bogus DNSSEC answer; validation is not demonstrated.\n'
fi
printf 'Note: this test does not prove whether DNSSEC validation occurs locally or upstream.\n'

printf '\n--- Negative answer comparison ---\n'
negative_name="missing-dns-audit-$(date +%s).iana.org"
negative_local="$REPORT_DIR/nxdomain-local.txt"
negative_ref="$REPORT_DIR/nxdomain-reference.txt"
query "$LOCAL_DNS" "$LOCAL_PORT" "$negative_name" A - "$negative_local" || true
query "$REFERENCE_DNS" 53 "$negative_name" A - "$negative_ref" || true
printf '%s: local=%s, reference=%s (expected NXDOMAIN)\n' "$negative_name" "$(rcode "$negative_local")" "$(rcode "$negative_ref")"

printf '\n--- Transport and EDNS tests ---\n'
for item in 'cloudflare.com|DNSKEY' 'crypto.cloudflare.com|TYPE65' '_25._tcp.mail.protonmail.ch|TLSA'; do
    IFS='|' read -r host typ <<< "$item"
    safe="${host//[^A-Za-z0-9]/_}-$typ"
    udp_file="$REPORT_DIR/transport-$safe-udp.txt"
    tcp_file="$REPORT_DIR/transport-$safe-tcp.txt"
    dig "@$LOCAL_DNS" -p "$LOCAL_PORT" "$host" "$typ" +dnssec +bufsize=1232 +ignore +time=3 +tries=1 +noall +comments +answer +stats > "$udp_file" 2>&1 || true
    dig "@$LOCAL_DNS" -p "$LOCAL_PORT" "$host" "$typ" +tcp +dnssec +time=3 +tries=1 +noall +comments +answer +stats > "$tcp_file" 2>&1 || true
    udp_tc='no'; flag_present "$udp_file" tc && udp_tc='yes'
    printf '%-38s %-7s UDP=%-10s TCP=%-10s UDP_TC=%s\n' "$host" "$typ" "$(rcode "$udp_file")" "$(rcode "$tcp_file")" "$udp_tc"
done

printf '\n--- Summary ---\n'
printf 'PASS=%s FAIL=%s WARN=%s SKIP=%s total=%s\n' "$pass" "$fail" "$warn" "$skip" "$idx"
printf 'Raw data is saved under: %s\n' "$REPORT_DIR"
printf 'SKIP means no positive reference answer or unreachable reference. Check raw logs for RRset differences.\n'