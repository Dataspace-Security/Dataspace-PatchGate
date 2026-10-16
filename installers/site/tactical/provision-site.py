# Runs INSIDE the Tactical backend container:  python manage.py shell < /tmp/pg-provision-site.py
# Options come from /tmp/pg-provision-args.json (written by install-site.sh):
#   {"client": "<bank name>", "site": "<site name>", "tokenHours": 72, "rotateKey": false, "scriptsDir": "/tmp/pg-scripts",
#    "keepBreakGlass": false, "breakGlassUser": "tacticaladmin" (optional; the lab passes its own admin)}
#
# Creates (idempotently) everything the PatchGate connector needs in a fresh Tactical, least privilege:
#   1. role "PatchGate service" with only the permissions the connector uses
#   2. service account patchgate-svc (no dashboard login) + API key (kept on re-runs unless rotateKey)
#   3. client + site
#   4. the three fixed PatchGate PowerShell scripts (bodies from scriptsDir; ids stable on re-runs)
#   5. every severity of EVERY patch policy = manual (Tactical never approves by itself)
#   6. a fresh agent install token (what Tactical's "Install agent" dialog creates) for the bank PCs
#   7. SEAL (RUNBOOK "Tactical is sealed"): dashboard login blocked for every user except the service account
#      (tacticaladmin = break-glass account, unblocked only with install-site.sh --break-glass on), their
#      dashboard sessions ended, every other API key expired; the seal is written to Tactical's audit log,
#      which the connector reports to PatchGate (TACTICAL_AUDIT_SYNC)
#   8. agent version fixed: Tactical's agent auto-update OFF (CoreSettings.agent_auto_update; the installer also
#      sets TRMM_DISABLE_AGENT_AUTO_UPDATE_TASK) - agents are upgraded only by PatchGate change requests
# Prints one line: PATCHGATE_PROVISION=<json>
import datetime as dt
import json
import os
import secrets

from django.core.cache import cache
from django.db import models
from django.utils import timezone
from knox.models import AuthToken

from accounts.models import APIKey, Role, User
from clients.models import Client, Site
from core.models import CoreSettings
from logs.models import AuditLog
from scripts.models import Script
from winupdate.models import WinUpdatePolicy

with open("/tmp/pg-provision-args.json", encoding="utf-8") as f:
    args = json.load(f)
client_name = str(args["client"])[:255]
site_name = str(args["site"])[:255]
token_hours = max(1, min(int(args.get("tokenHours", 72)), 24 * 30))
scripts_dir = args.get("scriptsDir", "/tmp/pg-scripts")

role, _ = Role.objects.update_or_create(
    name="PatchGate service",
    defaults=dict(
        is_superuser=False,
        can_list_agents=True,
        can_manage_winupdates=True,
        can_list_software=True,
        can_run_scripts=True,
        can_list_scripts=True,
        can_list_clients=True,
        can_list_sites=True,
        # Tactical seal: the connector reads the audit log (PATCH /logs/audit/) to report out-of-band actions
        can_view_auditlogs=True,
    ),
)

svc, created = User.objects.get_or_create(username="patchgate-svc", defaults={"email": "patchgate-svc@localhost"})
svc.role = role
svc.block_dashboard_login = True
svc.is_active = True
if created:
    svc.set_unusable_password()
svc.save()

existing = APIKey.objects.filter(user=svc, name="patchgate").first()
if existing is None or args.get("rotateKey"):
    APIKey.objects.filter(user=svc).delete()
    api_key = secrets.token_hex(24).upper()[:48]
    APIKey.objects.create(name="patchgate", key=api_key, user=svc)
    key_state = "created"
else:
    api_key = existing.key
    key_state = "kept"

client, _ = Client.objects.get_or_create(name=client_name)
site, _ = Site.objects.get_or_create(client=client, name=site_name)

SCRIPTS = [
    ("installScriptId", "PatchGate - Install package", "Install-PatchGatePackage.ps1", 900,
     "Installs PatchGate-approved packages from the site's PatchGate connector cache."),
    ("wuScanScriptId", "PatchGate - Windows Update offline scan", "Invoke-PatchGateWuScan.ps1", 3600,
     "Offline Windows Update scan against Microsoft's signed wsusscn2.cab from the connector cache (read-only)."),
    ("wuInstallScriptId", "PatchGate - Install Windows updates", "Install-PatchGateWinUpdate.ps1", 3600,
     "Installs PatchGate-approved Microsoft update files (.msu/.cab) from the connector cache."),
]
script_ids = {}
for key, name, filename, timeout, desc in SCRIPTS:
    with open(os.path.join(scripts_dir, filename), encoding="utf-8") as f:
        body = f.read()
    script, _ = Script.objects.update_or_create(
        name=name,
        defaults=dict(shell="powershell", category="PatchGate", script_body=body, default_timeout=timeout,
                      description=desc),
    )
    script_ids[key] = script.pk

SEVERITIES = ("critical", "important", "moderate", "low", "other")
policies_fixed = 0
for p in WinUpdatePolicy.objects.all():  # default, per-agent and automation-policy patch policies
    if any(getattr(p, s) != "manual" for s in SEVERITIES):
        for s in SEVERITIES:
            setattr(p, s, "manual")
        p.save()
        policies_fixed += 1

# --- 7. seal: nobody patches or installs through Tactical by hand -------------------------------------------
BREAK_GLASS_USER = str(args.get("breakGlassUser") or "tacticaladmin")  # lab: its Tactical admin is labadmin
keep_break_glass = bool(args.get("keepBreakGlass"))  # break-glass is ON right now (install-site.sh state)
now = timezone.now()
newly_blocked = []
other_users = []
for u in User.objects.filter(is_installer_user=False).exclude(pk=svc.pk):
    if u.username != BREAK_GLASS_USER:
        other_users.append(u.username)
    if u.username == BREAK_GLASS_USER and keep_break_glass:
        continue
    if not u.block_dashboard_login:
        User.objects.filter(pk=u.pk).update(block_dashboard_login=True)
        newly_blocked.append(u.username)
    AuthToken.objects.filter(user=u).delete()  # end open dashboard sessions (never the installer's PC tokens)
expired_keys = (
    APIKey.objects.exclude(user=svc)
    .filter(models.Q(expiration__isnull=True) | models.Q(expiration__gt=now))
    .update(expiration=now)
)
# --- 8. agent version fixed: no automatic agent upgrades by Tactical ----------------------------------------
auto_update_fixed = CoreSettings.objects.filter(agent_auto_update=True).update(agent_auto_update=False)
cache.delete("core_settings")  # tacticalrmm.constants.CORESETTINGS_CACHE_KEY (save() would clear it; update() does not)

if newly_blocked or expired_keys or policies_fixed or auto_update_fixed:
    AuditLog.objects.create(
        username="patchgate-provision",
        object_type="user",
        action="modify",
        message=("PatchGate seal: dashboard login blocked for %s; %d other API key(s) expired; %d patch policy(ies) set to manual%s"
                 % (", ".join(newly_blocked) or "nobody new", expired_keys, policies_fixed,
                    "; agent auto-update turned off" if auto_update_fixed else ""))[:255],
        debug_info={"source": "installers/site/tactical/provision-site.py"},
    )

installer = User.objects.filter(is_installer_user=True).first()
_, install_token = AuthToken.objects.create(user=installer, expiry=dt.timedelta(hours=token_hours))
expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=token_hours)).isoformat()

print("PATCHGATE_PROVISION=" + json.dumps({
    "apiKey": api_key,
    "apiKeyState": key_state,
    "clientId": client.pk,
    "siteId": site.pk,
    **script_ids,
    "installToken": install_token,
    "installTokenExpiresAt": expires,
    # seal report (flat strings: install-site.sh reads this JSON with sed)
    "sealBlocked": ";".join(newly_blocked),
    "sealOtherUsers": ";".join(other_users),
    "sealExpiredApiKeys": expired_keys,
    "sealPoliciesFixed": policies_fixed,
    "breakGlass": "on" if keep_break_glass else "off",
    "agentAutoUpdate": "off",
}))
