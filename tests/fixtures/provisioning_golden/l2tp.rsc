# ============================================================
# Bitwave ISP Auto-Provisioning Script
# Router: Router-0001 (Test Router)
# VPN Type: L2TP/IPsec
# Tunnel IP: 10.0.100.77
# Generated: 2026-09-26T12:00:00Z
# ============================================================

# ---- PRE-FLIGHT: HOTSPOT AVAILABILITY CHECK ----
# If the hotspot feature is unavailable its console menus do not exist and
# direct /ip hotspot references are PARSE errors that abort the import
# mid-way (half-provisioned router). Probe the menu via [:parse] so the
# failure happens at runtime, where it can be caught and turned into a
# clean abort BEFORE any configuration is applied.
:do {
    :local bwHsProbe [:parse "/ip hotspot profile find"]
    $bwHsProbe
    :log info "Provisioning: hotspot feature available"
} on-error={
    :log error "PROVISION ABORTED: the hotspot feature is not available on this router -- on RouterOS v6 this usually means the hotspot package is missing or disabled. Check: /system package print  -- enable the hotspot package, reboot, then re-run this provisioning command."
    :error "hotspot feature unavailable -- aborting before any config is applied (see /log print)"
}

# ---- STEP 1: WAN / INITIAL SETUP ----

:do { /interface wireless cap set enabled=no } on-error={}

:if ([:len [/interface bridge find where name=bridge]] = 0) do={
    /interface bridge add name=bridge
    :log info "Provisioning: created bridge interface"
} else={
    :log info "Provisioning: bridge interface already exists"
}

:foreach iface in={ether2;ether3;ether4;ether5} do={
    :do {
        :if ([:len [/interface find where name=$iface]] > 0) do={
            :if ([:len [/interface bridge port find where interface=$iface]] = 0) do={
                /interface bridge port add interface=$iface bridge=bridge
            }
        }
    } on-error={}
}

:do {
    :if ([:len [/interface find where name=wlan1]] > 0) do={
        :if ([:len [/interface bridge port find where interface=wlan1]] = 0) do={
            /interface bridge port add interface=wlan1 bridge=bridge
        }
    }
} on-error={}

:do { /interface bridge port remove [find where interface=ether1] } on-error={}
:do { /ip dhcp-client add interface=ether1 disabled=no comment="WAN uplink" } on-error={}
:do { /ip firewall nat add chain=srcnat out-interface=ether1 action=masquerade comment="NAT for internet access" } on-error={}
/ip dns set servers=8.8.8.8,8.8.4.4 allow-remote-requests=yes

:log info "Provisioning: WAN setup complete, waiting for DHCP lease..."
:delay 8s

# ---- STEP 2: LAN SETUP ----

:do { /ip address add address=192.168.88.1/24 interface=bridge } on-error={}
:do { /ip pool add name=dhcp-pool ranges=192.168.88.10-192.168.88.254 } on-error={}
:do { /ip dhcp-server add name=dhcp1 interface=bridge address-pool=dhcp-pool disabled=no } on-error={}
:do { /ip dhcp-server network add address=192.168.88.0/24 gateway=192.168.88.1 dns-server=8.8.8.8,8.8.4.4 } on-error={}

:log info "Provisioning: LAN and DHCP setup complete" 

# ---- STEP 3: L2TP/IPsec VPN (RouterOS v6) ----

:do {
    /interface l2tp-client add name=l2tp-aws connect-to=203.0.113.10 user="l2tp-Router-0001" password="L2tpPassword123" disabled=no allow=mschap2,mschap1 comment="Management VPN to AWS"
} on-error={
    /interface l2tp-client set [find where name=l2tp-aws] connect-to=203.0.113.10 user="l2tp-Router-0001" password="L2tpPassword123" disabled=no allow=mschap2,mschap1 comment="Management VPN to AWS"
}

# Some RouterOS v6 builds reject `use-ipsec` while importing an add command.
# Parse it at runtime so unsupported builds warn without aborting provisioning.
:do {
    :local bwSetIpsec [:parse "/interface l2tp-client set [find where name=l2tp-aws] use-ipsec=yes ipsec-secret=primary-psk"]
    $bwSetIpsec
    :log info "Provisioning: L2TP IPsec settings applied"
} on-error={
    :log warning "Provisioning: RouterOS rejected L2TP use-ipsec/ipsec-secret settings"
}
:do { /ip firewall filter add chain=input protocol=udp dst-port=500,4500,1701 action=accept comment="Allow L2TP/IPsec" } on-error={}

:log info "Provisioning: L2TP/IPsec tunnel configured, waiting for connection..."
:delay 15s

# Verify L2TP connected and got the expected IP
:local l2tpRunning [:len [/interface l2tp-client find where name=l2tp-aws running=yes]]
:if ($l2tpRunning = 0) do={
    :log warning "Provisioning: L2TP tunnel not yet connected -- will retry on reboot"
} else={
    :log info "Provisioning: L2TP tunnel connected"
}

# ---- STEP 3B: BACKUP L2TP/IPsec VPN (new server insurance tunnel) ----

:do {
    /interface l2tp-client add name=l2tp-aws2 connect-to=91.98.238.12 user="l2tp-Router-0001" password="L2tpPassword123" disabled=yes allow=mschap2,mschap1 add-default-route=no use-peer-dns=no comment="Standby management tunnel - enable only during failover"
} on-error={
    /interface l2tp-client set [find where name=l2tp-aws2] connect-to=91.98.238.12 user="l2tp-Router-0001" password="L2tpPassword123" disabled=yes allow=mschap2,mschap1 add-default-route=no use-peer-dns=no comment="Standby management tunnel - enable only during failover"
}

:do {
    :local bwSetInsuranceIpsec [:parse "/interface l2tp-client set [find where name=l2tp-aws2] use-ipsec=yes ipsec-secret=insurance-psk"]
    $bwSetInsuranceIpsec
    :log info "Provisioning: backup L2TP IPsec settings applied"
} on-error={
    :log warning "Provisioning: RouterOS rejected backup L2TP use-ipsec/ipsec-secret settings"
}

:log info "Provisioning: backup L2TP/IPsec tunnel staged disabled for single-active failover"
:delay 15s

# ---- STEP 4: HOTSPOT SETUP ----

:if ([:len [/interface bridge find where name=bridge]] = 0) do={
    :log error "PROVISION ABORTED at hotspot step: bridge interface missing"
    :error "bridge interface does not exist -- cannot create hotspot"
}

# Default html-directory. Works on:
#   - RouterOS v7 (unified persistent FS on every supported platform)
#   - RouterOS v6 CHR / x86 / unified-FS builds
# v6 RouterBOARDs with a split RAM/flash filesystem (legacy hEX, hAP, RB-
# series) need is_routerboard=true at token-creation time to switch to
# `flash/hotspot` instead.
:global bwHtmlDir "hotspot"
:log info "Provisioning: default html-directory=hotspot" 

# Clean legacy hotspot directories left behind by previous provisioners
# (CentiPid, OpenWISP, earlier versions of ours). This is best-effort and
# must never touch flash/etc*, flash/user-manager*, flash/skins, etc.
:do { /file remove [find where name="flash/centipid-hotspot"] } on-error={}
:foreach legacyId in=[/file find where name~"^flash/openwisp-hotspot" and type="directory"] do={
    :do { /file remove $legacyId } on-error={}
}

:do {
    /ip hotspot profile add name=hsprof1 hotspot-address=192.168.88.1 dns-name="" login-by=http-chap,http-pap html-directory=$bwHtmlDir
    :log info ("Provisioning: hotspot profile hsprof1 created with html-directory=" . $bwHtmlDir)
} on-error={
    :do { /ip hotspot profile set hsprof1 html-directory=$bwHtmlDir } on-error={
        :log warning "Provisioning: could not update hsprof1 html-directory, continuing"
    }
    :log info ("Provisioning: hotspot profile hsprof1 already existed, html-directory=" . $bwHtmlDir)
}

# Materialise RouterOS's default hotspot HTML file set into html-directory
# so our subsequent /tool fetch of login.html has a complete supporting
# set (rlogin.html, alogin.html, logout.html, md5.js, img/, ...). Works on
# RouterOS v6 and v7. NOTE: reset-html-directory takes the profile NAME
# as a positional argument -- it rejects [find where name=...] in the CLI
# parser even though most other commands accept that form.
:do {
    /ip hotspot profile reset-html-directory hsprof1
    :log info "Provisioning: hotspot profile reset-html-directory applied"
} on-error={
    :log warning "Provisioning: reset-html-directory not available on this RouterOS, continuing"
}

:do {
    /ip hotspot add name=hotspot1 interface=bridge address-pool=dhcp-pool profile=hsprof1 disabled=no
    :log info "Provisioning: hotspot1 created"
} on-error={
    :log warning "Provisioning: hotspot1 add failed (may already exist or hotspot feature unavailable)"
}

:local hsCount 0
:do {
    :set hsCount [:len [/ip hotspot find where name=hotspot1]]
} on-error={
    :log error "PROVISION WARNING: could not query hotspot -- the hotspot feature may not be available. Ensure device-mode hotspot is enabled: /system/device-mode/update hotspot=yes then press the physical reset button."
}
:if ($hsCount = 0) do={
    :log error "PROVISION WARNING: hotspot1 was not found -- hotspot feature may not be enabled. Run: /system/device-mode/update hotspot=yes then press the physical reset button."
} else={
    :log info "Provisioning: hotspot1 confirmed running"
}

:do { /interface bridge port remove [find where interface=ether1] } on-error={}

:log info "Provisioning: Hotspot step complete" 

# ---- STEP 5: DOWNLOAD CUSTOM LOGIN PAGE ----

:delay 2s

# Derive the destination from the hotspot profile so we always write into
# whatever html-directory step 4 picked: `flash/hotspot` for v6 RouterBOARDs
# provisioned with is_routerboard=true, `hotspot` everywhere else. Falls back
# to the $bwHtmlDir global, then to the legacy `hotspot` path if neither is
# available.
:local htmlDir ""
:do {
    :set htmlDir [/ip hotspot profile get hsprof1 html-directory]
} on-error={}
:if ([:len $htmlDir] = 0) do={
    :global bwHtmlDir
    :if ([:typeof $bwHtmlDir] = "str" and [:len $bwHtmlDir] > 0) do={
        :set htmlDir $bwHtmlDir
    } else={
        :set htmlDir "hotspot"
    }
}
:local loginPath ($htmlDir . "/login.html")
:log info ("Provisioning: downloading login page to " . $loginPath)

:local fetchOk false
:for i from=1 to=5 do={
    :if (!$fetchOk) do={
        :do {
            /tool fetch url="http://isp.example.net/api/provision/abc123/login-page" dst-path=$loginPath
            :set fetchOk true
            :log info ("Provisioning: Login page downloaded to " . $loginPath)
        } on-error={
            :log warning "Provisioning: Login page download attempt $i failed, retrying..."
            :delay 5s
        }
    }
}

# ---- STEP 6: WALLED GARDEN ----

/ip hotspot walled-garden add dst-host=isp-frontend-two.vercel.app action=allow comment="External Portal"
/ip hotspot walled-garden add dst-host="*.vercel.app" action=allow comment="Vercel CDN"
/ip hotspot walled-garden add dst-host=isp.bitwavetechnologies.net action=allow comment="Backend API (.net)"
/ip hotspot walled-garden add dst-host=isp.bitwavetechnologies.com action=allow comment="Backend API (.com)"
/ip hotspot walled-garden add dst-host=ispp.bitwavetechnologies.com action=allow comment="Backend API direct (not Cloudflare-proxied)"
:do { /ip hotspot walled-garden ip add dst-address=203.0.113.10/32 action=accept comment="Backend API IP" } on-error={}

:do { /ip hotspot walled-garden ip add dst-address=91.98.238.12/32 action=accept comment="Backup backend API IP" } on-error={}

:log info "Provisioning: Walled garden configured" 

# ---- STEP 7: ENABLE MIKROTIK API (restricted to VPN servers) ----

/ip service set api address=10.0.0.1/32,10.251.0.1/32 port=8728 disabled=no
:do { /ip firewall filter add chain=input protocol=tcp dst-port=8728 src-address=10.0.0.1 action=accept comment="Allow API from primary AWS" place-before=0 } on-error={}
:do { /ip firewall filter add chain=input protocol=tcp dst-port=8728 src-address=10.251.0.1 action=accept comment="Allow API from backup AWS" place-before=0 } on-error={}

# ---- STEP 8: CREATE API SERVICE ACCOUNT & SET IDENTITY ----

/system identity set name=Router-0001
:do { /user add name=bitwave-api password="ApiPassword123" group=full comment="Bitwave backend API account" } on-error={}

:log info "Provisioning: Identity set to Router-0001, API user created" 

# ---- STEP 9: REMOVE LEGACY OUTBOUND COMMAND AGENT ----

:do { /system scheduler remove [find name="bitwave-command-agent"] } on-error={}
:do { /system script remove [find name="bitwave-command-agent"] } on-error={}


# ---- STEP 9: NOTIFY SERVER ----

:delay 2s
:do {
    /tool fetch url="http://isp.example.net/api/provision/abc123/complete"
    :log info "Provisioning: Server notified -- router registered"
} on-error={
    :log warning "Provisioning: Could not notify server (register manually via admin panel)"
}

# ---- STEP 10: REBOOT ----

:log info "Provisioning complete! Rebooting in 5 seconds..."
:delay 5s
/system reboot
