# Runs INSIDE the Tactical backend container:  python manage.py shell < /tmp/pg-provision-site.py
# Options come from /tmp/pg-provision-args.json (written by install-site.sh):
#   {"client": "<bank name>", "site": "<site name>", "tokenHours": 72, "rotateKey": false, "scriptsDir": "/tmp/pg-scripts"}
#
# Creates (idempotently) everything the PatchGate connector needs in a fresh Tactical, least privilege:
#   1. role "PatchGate service" with only the permissions the connector uses
#   2. service account patchgate-svc (no dashboard login) + API key (kept on re-runs unless rotateKey)
#   3. client + site
#   4. the three fixed PatchGate PowerShell scripts (bodies from scriptsDir; ids stable on re-runs)
#   5. every severity of the default patch policy = manual (Tactical never approves by itself)
#   6. a fresh agent install token (what Tactical's "Install agent" dialog creates) for the bank PCs
# Prints one line: PATCHGATE_PROVISION=<json>
import datetime as dt
import json
import os
import secrets

from knox.models import AuthToken

from accounts.models import APIKey, Role, User
from clients.models import Client, Site
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

for p in WinUpdatePolicy.objects.filter(agent__isnull=True, policy__isnull=True):
    p.critical = p.important = p.moderate = p.low = p.other = "manual"
    p.save()

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
}))
