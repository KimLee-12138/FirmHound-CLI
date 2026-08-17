# 固件端到端静态分析报告

- rootfs: `C:\Users\22067\Desktop\揭榜挂帅——网络安全\tmp\unpacked\_DIR859_FW102b03.bin-0.extracted\squashfs-root`
- ELF 二进制: 113
- 脚本数: 1101
- 启动脚本: 9
- Web 端点: 892
- 检出候选: 29

## 1. 二进制 triage

| 二进制 | 架构 | triage | 危险命中 |
|--------|------|--------|----------|
| bin\busybox | mips | 0.20 | — |
| bin\mDNSResponderPosix | mips | 0.53 | calloc, fprintf, free, malloc, memcpy, memmove, printf, sprintf, sscanf, strcpy, strncpy, syslog |
| htdocs\cgibin | mips | 0.53 | access, execl, fprintf, free, getenv, malloc, memcpy, memmove, popen, printf, realloc, snprintf, sprintf, strcat, strcpy, strncpy, strtok, system, vsnprintf |
| htdocs\fileaccess.cgi | mips | 0.53 | access, calloc, execl, execv, fprintf, free, getenv, malloc, memcpy, memmove, popen, printf, realloc, snprintf, sprintf, sscanf, strcat, strcpy, strncpy, strtok, system, vsnprintf |
| lib\ld-uClibc.so.0 | mips | 0.00 | — |
| lib\libanwi.so | mips | 0.20 | fprintf, free, malloc, memcpy, printf, snprintf, strcpy |
| lib\libar9287.so | mips | 0.20 | calloc, free, malloc, memcpy, printf, snprintf, sprintf, strcat, strcpy, strncpy, vsnprintf |
| lib\libar9300.so | mips | 0.20 | calloc, free, malloc, memcpy, printf, snprintf, sprintf, strcat, strcpy, strncpy, vsnprintf |
| lib\libc.so.0 | mips | 0.00 | — |
| lib\libcal-2p.so | mips | 0.20 | memcpy, snprintf, strcpy |
| lib\libcrypt.so.0 | mips | 0.20 | memcpy, strcat, strcpy, strncat |
| lib\libcrypto.so.0.9.8 | mips | 0.53 | chmod, fprintf, free, getenv, malloc, memcpy, memmove, printf, realloc, sprintf, sscanf, strcat, strcpy, strncpy, syslog |
| lib\libdl.so.0 | mips | 0.20 | fprintf, free, getenv, malloc |
| lib\libfield.so | mips | 0.20 | free, malloc, memcpy, snprintf, strcpy, strncpy |
| lib\libgcc_s.so.1 | mips | 0.20 | calloc, free, malloc, memcpy, realloc |
| lib\libiconv.so.2.2.0 | mips | 0.20 | free, malloc, memcpy, realloc, strcpy |
| lib\liblinkAr9k.so | mips | 0.13 | memcpy |
| lib\libLinkQc9K.so | mips | 0.13 | memcpy |
| lib\liblzo2.so.2.0.0 | mips | 0.20 | memcpy, memmove |
| lib\libnsl.so.0 | mips | 0.00 | — |
| lib\libpart.so | mips | 0.33 | fprintf, free, malloc, memcpy, printf, snprintf, sscanf, strcat, strcpy, vsnprintf |
| lib\libpthread-0.9.30.so | mips | 0.33 | calloc, free, malloc, memcpy |
| lib\libqc98xx.so | mips | 0.53 | fprintf, free, malloc, memcpy, printf, snprintf, sprintf, sscanf, strcat, strcpy, strncpy, strtok |
| lib\libresolv.so.0 | mips | 0.00 | — |
| lib\librt.so.0 | mips | 0.13 | free, malloc |
| lib\libssl.so.0.9.8 | mips | 0.40 | fprintf, memcpy, memmove, strcpy |
| lib\libtlvtemplate.so | mips | 0.00 | — |
| lib\libtlvutil.so | mips | 0.20 | memcpy, printf |
| lib\libuuid.so.1.0.0 | mips | 0.20 | fprintf, memcpy, sprintf |
| lib\libwpa_common.so | mips | 0.53 | calloc, fprintf, free, malloc, memcpy, memmove, printf, realloc, setenv, snprintf, sscanf, strncpy, vsnprintf |
| lib\libwpa_ctrl.so | mips | 0.33 | calloc, fprintf, free, malloc, memcpy, setenv, snprintf |
| lib\libz.so.1.2.3 | mips | 0.20 | fprintf, free, malloc, memcpy, sprintf, strcat, strcpy, vsnprintf |
| lib\modules\adf.ko | mips | 0.13 | memcpy |
| lib\modules\art.ko | mips | 0.00 | — |
| lib\modules\asf.ko | mips | 0.00 | — |
| lib\modules\athrs_gmac.ko | mips | 0.40 | memcpy, memmove, sprintf |
| lib\modules\ath_dev.ko | mips | 0.20 | memcpy, snprintf, sscanf, vsnprintf |
| lib\modules\ath_dfs.ko | mips | 0.20 | memcpy, snprintf |
| lib\modules\ath_hal.ko | mips | 0.20 | memcpy, snprintf, vsnprintf |
| lib\modules\ath_pktlog.ko | mips | 0.20 | memcpy, snprintf |
| lib\modules\ath_rate_atheros.ko | mips | 0.00 | — |
| lib\modules\gpio.ko | mips | 0.00 | — |
| lib\modules\nf_conntrack_ipsec_pass.ko | mips | 0.13 | memcpy |
| lib\modules\nf_conntrack_ipv6.ko | mips | 0.20 | memcpy, memmove |
| lib\modules\nf_conntrack_pptp.ko | mips | 0.13 | memcpy |
| lib\modules\nf_conntrack_proto_gre.ko | mips | 0.13 | memcpy |
| lib\modules\nf_conntrack_rtsp.ko | mips | 0.20 | sprintf |
| lib\modules\nf_conntrack_sip.ko | mips | 0.20 | memcpy, sprintf |
| lib\modules\nf_nat_pptp.ko | mips | 0.00 | — |
| lib\modules\nf_nat_proto_gre.ko | mips | 0.00 | — |
| lib\modules\nf_nat_rtsp.ko | mips | 0.20 | memcpy, sprintf |
| lib\modules\nf_nat_sip.ko | mips | 0.20 | sprintf |
| lib\modules\rebootm.ko | mips | 0.20 | sprintf |
| lib\modules\umac.ko | mips | 0.40 | memcpy, memmove, snprintf, sprintf, sscanf, strcat, strncat, vsnprintf |
| sbin\80211stats | mips | 0.00 | — |
| sbin\athstats | mips | 0.00 | — |
| sbin\httpd | mips | 0.53 | execve, fprintf, free, getenv, malloc, memcpy, memmove, popen, printf, realloc, snprintf, sprintf, strcpy, strncpy, system, vsnprintf |
| sbin\nart.out | mips | 0.20 | fprintf, free, malloc, memcpy, memmove, printf, snprintf, sprintf, sscanf, strcat, strcpy, strtok, vsnprintf |
| sbin\radartool | mips | 0.00 | — |
| sbin\wlanconfig | mips | 0.00 | — |
| usr\lib\libnl-tiny.so | mips | 0.33 | calloc, fprintf, free, malloc, memcpy, realloc, snprintf, strncpy |
| usr\sbin\arpmonitor | mips | 0.33 | fprintf, free, malloc, memcpy, popen, printf, snprintf, sprintf, sscanf, strcpy, strncpy, strtok, system, vsnprintf |
| usr\sbin\cwmHelper | mips | 0.33 | fprintf, popen, snprintf, sprintf, system, vsnprintf |
| usr\sbin\ddnsd | mips | 0.53 | chmod, fprintf, free, malloc, memcpy, printf, realloc, snprintf, sprintf, strcat, strcpy, strncpy, syslog, system, vsnprintf |
| usr\sbin\dhcp6-multi | mips | 0.33 | execve, fprintf, free, malloc, memcpy, realloc, snprintf, sprintf, sscanf, strcpy, strncpy, syslog, system, vsnprintf |
| usr\sbin\dnsmasq | mips | 0.33 | execl, fprintf, free, malloc, memcpy, memmove, popen, printf, setenv, snprintf, sprintf, strcat, strcpy, strncat, strncpy, strtok, system, vsnprintf |
| usr\sbin\email | mips | 0.33 | execlp, fprintf, free, getenv, malloc, memcpy, memmove, popen, printf, putenv, realloc, snprintf, strtok, system, vsnprintf |
| usr\sbin\ethreg | mips | 0.33 | fprintf, memcpy, printf, strncpy |
| usr\sbin\fileaccessd | mips | 0.53 | free, getenv, malloc, memcpy, popen, realloc, snprintf, sprintf, strcat, strcpy, strncpy, system, vsnprintf |
| usr\sbin\gdataclient | mips | 0.53 | fprintf, free, malloc, memcpy, popen, snprintf, sprintf, strcpy, system, vsnprintf |
| usr\sbin\gpioc | mips | 0.20 | calloc, free, printf |
| usr\sbin\gpiod | mips | 0.33 | fprintf, free, malloc, popen, printf, snprintf, strncpy, syslog, system, vsnprintf, vsprintf |
| usr\sbin\hostapd | mips | 0.53 | calloc, chmod, chown, execvp, fprintf, free, malloc, memcpy, memmove, popen, printf, realloc, snprintf, sprintf, sscanf, strcat, strcpy, strncpy, system, vsnprintf |
| usr\sbin\ip | mips | 0.33 | fprintf, free, getenv, malloc, memcpy, printf, realloc, snprintf, sprintf, sscanf, strcat, strcpy, strncpy, strtok |
| usr\sbin\ip6tables-multi | mips | 0.53 | calloc, execv, fprintf, free, getenv, malloc, memcpy, printf, realloc, snprintf, sprintf, sscanf, strcat, strcpy, strncpy, strtok |
| usr\sbin\iptables-multi | mips | 0.53 | calloc, execv, fprintf, free, getenv, malloc, memcpy, printf, realloc, snprintf, sprintf, sscanf, strcat, strcpy, strncpy, strtok |
| usr\sbin\iwconfig | mips | 0.33 | fprintf, free, malloc, memcpy, printf, realloc, snprintf, sprintf, sscanf, strcpy, strncpy, strtok |
| usr\sbin\iwlist | mips | 0.33 | fprintf, free, malloc, memcpy, printf, realloc, snprintf, sprintf, sscanf, strcpy, strncpy, strtok |
| usr\sbin\iwpriv | mips | 0.33 | fprintf, free, malloc, memcpy, printf, realloc, snprintf, sprintf, sscanf, strcpy, strncpy, strtok |
| usr\sbin\klogd | mips | 0.53 | popen, printf, snprintf, sprintf, strncpy, syslog |
| usr\sbin\lld2d | mips | 0.53 | fprintf, free, malloc, memcpy, popen, snprintf, sprintf, strcat, strcpy, strncpy, system, vsnprintf |
| usr\sbin\logd | mips | 0.33 | fprintf, free, malloc, memcpy, popen, printf, realloc, snprintf, sprintf, strcpy, strncpy, system, vsnprintf |
| usr\sbin\logger | mips | 0.20 | printf, syslog |
| usr\sbin\mrd | mips | 0.33 | free, malloc, memcpy, popen, printf, realloc, snprintf, sprintf, sscanf, strcpy, strncpy, system, vsnprintf |
| usr\sbin\nameresolv | mips | 0.33 | fprintf, free, malloc, memcpy, printf, sscanf, strcat, strcpy, strncat, strncpy |
| usr\sbin\nsbbox | mips | 0.33 | fprintf, free, getenv, malloc, memcpy, popen, printf, snprintf, sprintf, sscanf, strcpy, strncpy, syslog, system, vsnprintf |
| usr\sbin\peanut | mips | 0.53 | chmod, fprintf, malloc, memcpy, memmove, popen, printf, snprintf, sprintf, strcpy, strncat, strtok, syslog, system, vsnprintf |
| usr\sbin\portt | mips | 0.33 | free, memcpy, printf, sprintf, strcpy, strncpy, system, vsnprintf |
| usr\sbin\pppd | mips | 0.33 | chmod, execv, execve, fprintf, free, malloc, memcpy, memmove, printf, realloc, snprintf, sprintf, strcat, strcpy, strncat, strncpy, strtok, syslog, system, vsnprintf |
| usr\sbin\proxyd | mips | 0.53 | fprintf, free, malloc, memcpy, memmove, printf, realloc, snprintf, sprintf, strcat, strcpy, strncpy, strtok, vsnprintf |
| usr\sbin\radvd | mips | 0.33 | access, calloc, fprintf, free, malloc, memcpy, realloc, snprintf, sscanf, strcat, strcpy, strncat, strncpy, syslog, vsnprintf |
| usr\sbin\radvdump | mips | 0.33 | fprintf, malloc, printf, strcat, strcpy, strncat, syslog, vsnprintf |
| usr\sbin\rdisc6 | mips | 0.33 | execve, fprintf, free, malloc, memcpy, printf, realloc, snprintf, sprintf, strcat, strcpy, strncpy, system |
| usr\sbin\rgbin | mips | 0.53 | access, calloc, chmod, fprintf, free, malloc, memcpy, memmove, popen, printf, realloc, snprintf, sprintf, sscanf, strcat, strcpy, strncpy, strtok, system, vsnprintf |
| usr\sbin\rndimage | mips | 0.20 | fprintf, free, malloc, memcpy, printf, realloc, sprintf |
| usr\sbin\servd | mips | 0.33 | chmod, execle, fprintf, free, malloc, memcpy, printf, realloc, snprintf, sprintf, sscanf, strcpy, strtok, system, vsnprintf |
| usr\sbin\ssdk_sh | mips | 0.00 | — |
| usr\sbin\stunnel | mips | 0.33 | calloc, free, memcpy, printf, sprintf, strncpy |
| usr\sbin\tc | mips | 0.33 | calloc, fprintf, free, getenv, malloc, memcpy, printf, realloc, snprintf, sprintf, sscanf, strcat, strcpy, strncpy, strtok |
| usr\sbin\telnetd | mips | 0.33 | access, execv, fprintf, free, malloc, memcpy, memmove, printf, strcpy, strncpy |
| usr\sbin\trigger | mips | 0.33 | free, printf, strncpy |
| usr\sbin\ubcfg | mips | 0.20 | free, malloc, printf, strcat, strncpy |
| usr\sbin\ubiattach | mips | 0.20 | calloc, fprintf, free, malloc, memcpy, printf, sprintf, sscanf, strncpy |
| usr\sbin\ubidetach | mips | 0.20 | calloc, fprintf, free, malloc, memcpy, printf, sprintf, sscanf, strncpy |
| usr\sbin\ubiformat | mips | 0.20 | calloc, fprintf, free, malloc, memcpy, printf, sprintf, sscanf, strcpy, strncpy |
| usr\sbin\ubimkvol | mips | 0.20 | calloc, fprintf, free, malloc, memcpy, printf, sprintf, sscanf, strncpy |
| usr\sbin\ubirmvol | mips | 0.20 | calloc, fprintf, free, malloc, memcpy, printf, sprintf, sscanf, strncpy |
| usr\sbin\ubiupdatevol | mips | 0.20 | calloc, fprintf, free, malloc, memcpy, printf, sprintf, sscanf, strncpy |
| usr\sbin\udhcpd | mips | 0.33 | execle, fprintf, free, malloc, memcpy, printf, realloc, sprintf, strcpy, strncpy, strtok, syslog, system |
| usr\sbin\updateleases | mips | 0.33 | malloc, popen, snprintf, sprintf, strcpy, strncpy, system, vsnprintf |
| usr\sbin\widget | mips | 0.20 | printf, snprintf, sprintf |
| usr\sbin\wpatalk | mips | 0.53 | access, fprintf, free, getenv, memcpy, memmove, printf, snprintf, sprintf, strcpy, strncpy, system |
| usr\sbin\xmldb | mips | 0.33 | calloc, chmod, fprintf, free, malloc, memcpy, popen, printf, realloc, snprintf, sprintf, strcat, strcpy, strncpy, system, vsnprintf |

## 2. 检出候选（命令注入）

| 候选 | 二进制 | Sink | 分数 | 等级 |
|------|--------|------|------|------|
| e2e-elf-arpmonitor | usr\sbin\arpmonitor | popen | 23 | HIGH |
| e2e-elf-cgibin | htdocs\cgibin | popen | 23 | HIGH |
| e2e-elf-cwmHelper | usr\sbin\cwmHelper | popen | 23 | HIGH |
| e2e-elf-ddnsd | usr\sbin\ddnsd | system | 23 | HIGH |
| e2e-elf-dhcp6-multi | usr\sbin\dhcp6-multi | system | 23 | HIGH |
| e2e-elf-dnsmasq | usr\sbin\dnsmasq | popen | 23 | HIGH |
| e2e-elf-email | usr\sbin\email | popen | 23 | HIGH |
| e2e-elf-fileaccess.cgi | htdocs\fileaccess.cgi | popen | 23 | HIGH |
| e2e-elf-fileaccessd | usr\sbin\fileaccessd | popen | 23 | HIGH |
| e2e-elf-gdataclient | usr\sbin\gdataclient | popen | 23 | HIGH |
| e2e-elf-gpiod | usr\sbin\gpiod | popen | 23 | HIGH |
| e2e-elf-hostapd | usr\sbin\hostapd | popen | 23 | HIGH |
| e2e-elf-httpd | sbin\httpd | popen | 23 | HIGH |
| e2e-elf-klogd | usr\sbin\klogd | popen | 23 | HIGH |
| e2e-elf-lld2d | usr\sbin\lld2d | popen | 23 | HIGH |
| e2e-elf-logd | usr\sbin\logd | popen | 23 | HIGH |
| e2e-elf-mrd | usr\sbin\mrd | popen | 23 | HIGH |
| e2e-elf-nsbbox | usr\sbin\nsbbox | popen | 23 | HIGH |
| e2e-elf-peanut | usr\sbin\peanut | popen | 23 | HIGH |
| e2e-elf-portt | usr\sbin\portt | system | 23 | HIGH |
| e2e-elf-pppd | usr\sbin\pppd | system | 23 | HIGH |
| e2e-elf-rdisc6 | usr\sbin\rdisc6 | system | 23 | HIGH |
| e2e-elf-rgbin | usr\sbin\rgbin | popen | 23 | HIGH |
| e2e-elf-servd | usr\sbin\servd | system | 23 | HIGH |
| e2e-elf-udhcpd | usr\sbin\udhcpd | system | 23 | HIGH |
| e2e-elf-updateleases | usr\sbin\updateleases | popen | 23 | HIGH |
| e2e-elf-wpatalk | usr\sbin\wpatalk | system | 23 | HIGH |
| e2e-elf-xmldb | usr\sbin\xmldb | popen | 23 | HIGH |
| e2e-cgi-fileaccess.cgi | htdocs\fileaccess.cgi | eval | 21 | HIGH |
