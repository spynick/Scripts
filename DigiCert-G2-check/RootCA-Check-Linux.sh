#!/bin/bash
# ============================================
# RootCA-Check-Linux.sh
# DigiCert Global Root G2 - Check & Install
# ============================================
#
# Checks if the DigiCert Global Root G2 certificate
# is trusted on Linux systems. If missing, downloads
# and installs it automatically.
#
# Uses only standard tools (openssl, curl/wget).
#
# Usage:
#   ./RootCA-Check-Linux.sh              Check and install if missing
#   ./RootCA-Check-Linux.sh --check-only Check only, do not install
#
# Required for Exchange Online mail flow.
# Deadline: April 30, 2026
# Reference: https://aka.ms/DigiCertRootG2
#
# Thumbprint (SHA1): DF3C24F9BFD666761B268073FE06D1CC8D4F82A4
#
# Exit Codes:
#   0 = Certificate found or successfully installed
#   1 = Certificate missing (check-only) or install failed
#   2 = Error (missing tools, no CA store, etc.)
#
# ============================================

THUMBPRINT="df3c24f9bfd666761b268073fe06d1cc8d4f82a4"
CERT_NAME="DigiCert Global Root G2"
DOWNLOAD_URL="https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem"
CHECK_ONLY=0

if [ "$1" = "--check-only" ]; then
    CHECK_ONLY=1
fi

# ---- Helper functions ----

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: Root privileges required for installation. Run with sudo."
        exit 2
    fi
}

detect_distro() {
    # Returns: debian, redhat, suse, alpine, unknown
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|linuxmint|pop) echo "debian" ;;
            rhel|centos|fedora|rocky|alma|ol) echo "redhat" ;;
            sles|opensuse*) echo "suse" ;;
            alpine) echo "alpine" ;;
            *) echo "unknown" ;;
        esac
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "redhat"
    elif [ -f /etc/SuSE-release ]; then
        echo "suse"
    elif [ -f /etc/alpine-release ]; then
        echo "alpine"
    else
        echo "unknown"
    fi
}

download_file() {
    local url="$1"
    local dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url" 2>/dev/null
    else
        echo "ERROR: Neither curl nor wget found."
        exit 2
    fi
}

# ---- Check if openssl is available ----

if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl not found."
    exit 2
fi

# ---- Locate CA store ----

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

# ---- Check: Search in CA bundle ----

FOUND=0

if [ -n "$CA_BUNDLE" ]; then
    awk 'BEGIN {c=0} /BEGIN CERT/{c++} c>0{print > "/tmp/rootca_check_cert_" c ".pem"} /END CERT/{c=0}' "$CA_BUNDLE" 2>/dev/null
    for f in /tmp/rootca_check_cert_*.pem; do
        [ -f "$f" ] || continue
        fp=$(openssl x509 -in "$f" -noout -fingerprint -sha1 2>/dev/null | tr -d ':' | cut -d= -f2 | tr 'A-F' 'a-f')
        if [ "$fp" = "$THUMBPRINT" ]; then
            subj=$(openssl x509 -in "$f" -noout -subject 2>/dev/null)
            enddate=$(openssl x509 -in "$f" -noout -enddate 2>/dev/null)
            FOUND=1
            echo "COMPLIANT: $CERT_NAME certificate found in $CA_BUNDLE"
            echo "  $subj"
            echo "  $enddate"
        fi
        rm -f "$f"
    done
    rm -f /tmp/rootca_check_cert_*.pem
fi

# ---- Check: Search individual cert files ----

if [ "$FOUND" -eq 0 ] && [ -n "$CA_CERT_DIR" ]; then
    for cert in "$CA_CERT_DIR"/*.pem "$CA_CERT_DIR"/*.crt; do
        [ -f "$cert" ] || continue
        fp=$(openssl x509 -in "$cert" -noout -fingerprint -sha1 2>/dev/null | tr -d ':' | cut -d= -f2 | tr 'A-F' 'a-f')
        if [ "$fp" = "$THUMBPRINT" ]; then
            subj=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null)
            enddate=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null)
            FOUND=1
            echo "COMPLIANT: $CERT_NAME certificate found in $cert"
            echo "  $subj"
            echo "  $enddate"
            break
        fi
    done
fi

# ---- Already installed ----

if [ "$FOUND" -eq 1 ]; then
    exit 0
fi

# ---- Not found ----

echo "NON-COMPLIANT: $CERT_NAME certificate NOT found (SHA1: $THUMBPRINT)."

if [ "$CHECK_ONLY" -eq 1 ]; then
    echo "Run without --check-only to install automatically."
    exit 1
fi

# ---- Install ----

check_root

DISTRO=$(detect_distro)
TMPFILE=$(mktemp /tmp/DigiCertGlobalRootG2.XXXXXX.pem)

echo "Downloading $CERT_NAME certificate..."
download_file "$DOWNLOAD_URL" "$TMPFILE"

if [ ! -s "$TMPFILE" ]; then
    # Fallback: try DER format and convert
    TMPDER=$(mktemp /tmp/DigiCertGlobalRootG2.XXXXXX.crt)
    download_file "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt" "$TMPDER"
    if [ -s "$TMPDER" ]; then
        openssl x509 -inform DER -in "$TMPDER" -out "$TMPFILE" 2>/dev/null
    fi
    rm -f "$TMPDER"
fi

if [ ! -s "$TMPFILE" ]; then
    echo "ERROR: Failed to download certificate."
    rm -f "$TMPFILE"
    exit 1
fi

# Verify downloaded cert has correct thumbprint
DL_FP=$(openssl x509 -in "$TMPFILE" -noout -fingerprint -sha1 2>/dev/null | tr -d ':' | cut -d= -f2 | tr 'A-F' 'a-f')
if [ "$DL_FP" != "$THUMBPRINT" ]; then
    echo "ERROR: Downloaded certificate thumbprint mismatch!"
    echo "  Expected: $THUMBPRINT"
    echo "  Got:      $DL_FP"
    rm -f "$TMPFILE"
    exit 1
fi

echo "Installing certificate (detected distro: $DISTRO)..."

case "$DISTRO" in
    debian)
        cp "$TMPFILE" /usr/local/share/ca-certificates/DigiCertGlobalRootG2.crt
        update-ca-certificates
        ;;
    redhat)
        cp "$TMPFILE" /etc/pki/ca-trust/source/anchors/DigiCertGlobalRootG2.pem
        update-ca-trust
        ;;
    suse)
        cp "$TMPFILE" /etc/pki/trust/anchors/DigiCertGlobalRootG2.pem
        update-ca-certificates
        ;;
    alpine)
        cat "$TMPFILE" >> /etc/ssl/certs/ca-certificates.crt
        ;;
    *)
        # Generic fallback: try both common methods
        if [ -d /usr/local/share/ca-certificates ]; then
            cp "$TMPFILE" /usr/local/share/ca-certificates/DigiCertGlobalRootG2.crt
            if command -v update-ca-certificates >/dev/null 2>&1; then
                update-ca-certificates
            fi
        elif [ -d /etc/pki/ca-trust/source/anchors ]; then
            cp "$TMPFILE" /etc/pki/ca-trust/source/anchors/DigiCertGlobalRootG2.pem
            if command -v update-ca-trust >/dev/null 2>&1; then
                update-ca-trust
            fi
        else
            echo "ERROR: Unknown distro. Could not determine install path."
            echo "Manual install: copy $TMPFILE to your CA trust store and update."
            rm -f "$TMPFILE"
            exit 1
        fi
        ;;
esac

rm -f "$TMPFILE"

# ---- Verify installation ----

echo "Verifying installation..."
sleep 1

# Re-check the bundle
VERIFY=0
for path in $CA_PATHS; do
    [ -f "$path" ] || continue
    if grep -q "DigiCert Global Root G2" "$path" 2>/dev/null; then
        VERIFY=1
        break
    fi
done

if [ "$VERIFY" -eq 1 ]; then
    echo "SUCCESS: $CERT_NAME certificate installed and trusted."
    exit 0
else
    echo "WARNING: Installation completed but could not verify in CA bundle."
    echo "You may need to restart services that use TLS."
    exit 0
fi
