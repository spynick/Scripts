#!/bin/bash
# ============================================
# RootCA-Check-Linux.sh
# DigiCert Global Root G2 - Detection Script
# ============================================
#
# Checks if the DigiCert Global Root G2 certificate
# is trusted on Linux systems.
#
# Uses only standard tools (openssl, awk, grep).
#
# Required for Exchange Online mail flow.
# Deadline: April 30, 2026
# Reference: https://aka.ms/DigiCertRootG2
#
# Thumbprint (SHA1): DF3C24F9BFD666761B268073FE06D1CC8D4F82A4
#
# Exit Codes:
#   0 = Certificate found (compliant)
#   1 = Certificate NOT found (non-compliant)
#   2 = Error (openssl not available or ca-bundle not found)
#
# ============================================

THUMBPRINT="df3c24f9bfd666761b268073fe06d1cc8d4f82a4"
CERT_NAME="DigiCert Global Root G2"

# Check if openssl is available
if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl not found."
    exit 2
fi

# Common CA bundle locations across distros
CA_PATHS="
/etc/ssl/certs/ca-certificates.crt
/etc/pki/tls/certs/ca-bundle.crt
/etc/ssl/ca-bundle.pem
/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
/etc/ssl/cert.pem
"

CA_BUNDLE=""
for path in $CA_PATHS; do
    if [ -f "$path" ]; then
        CA_BUNDLE="$path"
        break
    fi
done

# Fallback: check individual cert directory
CA_CERT_DIR=""
if [ -d "/etc/ssl/certs" ]; then
    CA_CERT_DIR="/etc/ssl/certs"
elif [ -d "/etc/pki/tls/certs" ]; then
    CA_CERT_DIR="/etc/pki/tls/certs"
fi

if [ -z "$CA_BUNDLE" ] && [ -z "$CA_CERT_DIR" ]; then
    echo "ERROR: No CA certificate store found."
    exit 2
fi

# Method 1: Search in CA bundle file
if [ -n "$CA_BUNDLE" ]; then
    # Extract each certificate and check its fingerprint
    FOUND=$(awk 'BEGIN {c=0} /BEGIN CERT/{c++} c>0{print > "/tmp/rootca_check_cert_" c ".pem"} /END CERT/{c=0}' "$CA_BUNDLE" 2>/dev/null && \
        for f in /tmp/rootca_check_cert_*.pem; do
            fp=$(openssl x509 -in "$f" -noout -fingerprint -sha1 2>/dev/null | tr -d ':' | cut -d= -f2 | tr 'A-F' 'a-f')
            if [ "$fp" = "$THUMBPRINT" ]; then
                subj=$(openssl x509 -in "$f" -noout -subject 2>/dev/null)
                enddate=$(openssl x509 -in "$f" -noout -enddate 2>/dev/null)
                echo "$subj|$enddate"
            fi
            rm -f "$f"
        done)

    # Cleanup any remaining temp files
    rm -f /tmp/rootca_check_cert_*.pem

    if [ -n "$FOUND" ]; then
        echo "COMPLIANT: $CERT_NAME certificate found in $CA_BUNDLE"
        echo "$FOUND" | tr '|' '\n'
        exit 0
    fi
fi

# Method 2: Search individual cert files
if [ -n "$CA_CERT_DIR" ]; then
    for cert in "$CA_CERT_DIR"/*.pem "$CA_CERT_DIR"/*.crt; do
        [ -f "$cert" ] || continue
        fp=$(openssl x509 -in "$cert" -noout -fingerprint -sha1 2>/dev/null | tr -d ':' | cut -d= -f2 | tr 'A-F' 'a-f')
        if [ "$fp" = "$THUMBPRINT" ]; then
            subj=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null)
            enddate=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null)
            echo "COMPLIANT: $CERT_NAME certificate found in $cert"
            echo "$subj"
            echo "$enddate"
            exit 0
        fi
    done
fi

echo "NON-COMPLIANT: $CERT_NAME certificate NOT found (SHA1: $THUMBPRINT)."
echo "Install with: sudo apt install ca-certificates (Debian/Ubuntu)"
echo "         or:  sudo yum reinstall ca-certificates (RHEL/CentOS)"
echo "         or:  sudo update-ca-certificates / sudo update-ca-trust"
exit 1
