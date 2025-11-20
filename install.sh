#!/data/data/com.termux/files/usr/bin/bash
# CELLINT-RC Installation Script
# Requires Termux environment

echo -e "\033[94m[+] Installing CELLINT-RC System-Wide...\033[0m"

# Install required dependencies
pkg update -y
pkg install -y python termux-api 

# Create installation directory
INSTALL_DIR="$PREFIX/share/cellint-rc"
mkdir -p $INSTALL_DIR

# Copy main application
cp cellint-rc.py $INSTALL_DIR/
chmod +x $INSTALL_DIR/cellint-rc.py

# Create executable symlink
ln -sf $INSTALL_DIR/cellint-rc.py $PREFIX/bin/cellint-rc

# Install manpage
mkdir -p $PREFIX/share/man/man1
echo '.TH CELLINT-RC 1 "2024-05-01" "CELLINT-RC v2.1" "CELL Intelligence Console"
.SH NAME
cellint-rc \- Cell Intelligence Reconnaissance Console
.SH SYNOPSIS
.B cellint-rc
.SH DESCRIPTION
Comprehensive mobile device analysis and tracking tool for Android (Termux). Collects cellular network data, location information, and device parameters.
.SH COMMANDS
.TP
.B live
Real-time monitoring mode
.TP
.B scan cell
Perform cell tower scan
.TP
.B track device
Get current location
.TP
.B calculate imsi/imei
Generate possible identifiers
.TP
.B list devices
Show known devices
.TP
.B import
Parse Network Cell Info reports
.SH FILES
.I $PREFIX/share/cellint-rc/devices.json
Device database
.I $PREFIX/share/cellint-rc/rigint_operations.log
Operation log
.SH AUTHOR
D373Y 5373M / @eval
.SH SEE ALSO
termux-location(1), termux-telephony-cellinfo(1)' > $PREFIX/share/man/man1/cellint-rc.1

gzip $PREFIX/share/man/man1/cellint-rc.1

echo -e "\033[92m[+] Installation Complete!\033[0m"
echo -e "Run with: \033[1mcellint-rc\033[0m"
echo -e "View manual: \033[1mman cellint-rc\033[0m"
