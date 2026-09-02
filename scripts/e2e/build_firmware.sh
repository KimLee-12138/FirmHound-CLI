#!/bin/bash
# Build a synthetic firmware image containing a known command-injection
# vulnerability, then pack + unpack it. Run inside WSL (Ubuntu-22.04).
set -e
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"

WORK=/tmp/fw_demo_build
OUT=/mnt/c/temp/fw_demo
rm -rf "$WORK" "$OUT"
mkdir -p "$WORK/rootfs/bin" "$WORK/rootfs/www/cgi-bin" \
         "$WORK/rootfs/etc/init.d" "$WORK/rootfs/usr/sbin" "$WORK/rootfs/lib" "$OUT"

echo "[1/7] compiling httpd (command injection via formexeCommand)"
cat > "$WORK/httpd.c" << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void formexeCommand(char *cmd) {
    char buf[256];
    sprintf(buf, "%s; reboot", cmd);
    system(buf);
}

int main(int argc, char **argv) {
    char *cmd = getenv("QUERY_STRING");
    if (cmd) formexeCommand(cmd);
    return 0;
}
CEOF
gcc -o "$WORK/rootfs/bin/httpd" "$WORK/httpd.c"

echo "[2/7] compiling upnpd (command injection via snprintf+system, HG532e-like)"
cat > "$WORK/upnpd.c" << 'CEOF'
#include <stdio.h>
#include <stdlib.h>

void Upgrade(char *url) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "upg -g -U %s -r %s", url, url);
    system(cmd);
}

int main(void) {
    char *url = getenv("NewDownloadURL");
    if (url) Upgrade(url);
    return 0;
}
CEOF
gcc -o "$WORK/rootfs/usr/sbin/upnpd" "$WORK/upnpd.c"

echo "[3/7] writing CGI scripts (command injection)"
cat > "$WORK/rootfs/www/cgi-bin/ping.cgi" << 'CEOF'
#!/bin/sh
# command injection: QUERY_STRING unsanitized
eval "ping -c 4 $QUERY_STRING"
CEOF
chmod +x "$WORK/rootfs/www/cgi-bin/ping.cgi"

cat > "$WORK/rootfs/www/cgi-bin/systemtools.cgi" << 'CEOF'
#!/bin/sh
# command injection via cmd param
cmd=$(echo "$QUERY_STRING" | cut -d= -f2)
$cmd
CEOF
chmod +x "$WORK/rootfs/www/cgi-bin/systemtools.cgi"

echo "[4/7] writing startup script"
cat > "$WORK/rootfs/etc/init.d/rcS" << 'CEOF'
#!/bin/sh
/bin/httpd -p 80 &
/usr/sbin/upnpd &
CEOF
chmod +x "$WORK/rootfs/etc/init.d/rcS"

echo "[5/7] writing synthetic fixture support files"
echo "busybox" > "$WORK/rootfs/bin/busybox"
echo "root:x:0:0:root:/root:/bin/sh" > "$WORK/rootfs/etc/passwd"
echo "<html>synthetic regression router</html>" > "$WORK/rootfs/www/index.html"

echo "[6/7] packing squashfs firmware"
mksquashfs "$WORK/rootfs" "$OUT/firmware.bin" -noappend -quiet

echo "[7/7] unpacking back (verification)"
mkdir -p "$OUT/rootfs"
unsquashfs -d "$OUT/rootfs" "$OUT/firmware.bin" >/dev/null

echo "=== done ==="
ls -la "$OUT/"
echo "--- httpd ELF ---"
file "$WORK/rootfs/bin/httpd"
echo "--- httpd danger strings ---"
strings "$WORK/rootfs/bin/httpd" | grep -iE "system|sprintf|formexeCommand|QUERY_STRING" || true
echo "--- extracted rootfs files ---"
find "$OUT/rootfs" -type f | sed "s#$OUT/rootfs/##" | sort
