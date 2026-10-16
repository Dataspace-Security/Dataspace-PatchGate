# Runs INSIDE the Tactical backend (python manage.py shell < provision.py).
# Creates everything PatchGate needs in a fresh Tactical — least privilege — and prints JSON.
import datetime as dt
import json
import secrets

from django.conf import settings
from knox.models import AuthToken

from accounts.models import APIKey, Role, User
from clients.models import Client, Site
from scripts.models import Script
from winupdate.models import WinUpdatePolicy

# 1. Least-privilege role: only what PatchGate's API client uses.
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

# 2. Service account (cannot log in to the dashboard) + API key.
svc, created = User.objects.get_or_create(username="patchgate-svc", defaults={"email": "patchgate@lab.local"})
svc.role = role
svc.block_dashboard_login = True
svc.is_active = True
if created:
    svc.set_unusable_password()
svc.save()
APIKey.objects.filter(user=svc).delete()
api_key = secrets.token_hex(24).upper()[:48]
APIKey.objects.create(name="patchgate", key=api_key, user=svc)

# 3. Lab client/site (a bank and a branch).
client, _ = Client.objects.get_or_create(name="Lab Bank")
site, _ = Site.objects.get_or_create(client=client, name="Branch-001 Pune")

# 4. The fixed PatchGate scripts (bodies uploaded from patchgate-web/scripts/endpoint). The connector only ever
#    runs these three ids (tactical.installScriptId / wuScanScriptId / wuInstallScriptId in connector.json).
SCRIPTS = [
    ("installScriptId", "PatchGate - Install package", "/tmp/Install-PatchGatePackage.ps1", 900,
     "Installs PatchGate-approved packages from the site's PatchGate connector cache."),
    ("wuScanScriptId", "PatchGate - Windows Update offline scan", "/tmp/Invoke-PatchGateWuScan.ps1", 3600,
     "Offline Windows Update scan against Microsoft's signed wsusscn2.cab from the connector cache (read-only)."),
    ("wuInstallScriptId", "PatchGate - Install Windows updates", "/tmp/Install-PatchGateWinUpdate.ps1", 3600,
     "Installs PatchGate-approved Microsoft update files (.msu/.cab) from the connector cache."),
]
script_ids = {}
for key, name, path, timeout, desc in SCRIPTS:
    with open(path, encoding="utf-8") as f:
        body = f.read()
    script, _ = Script.objects.update_or_create(
        name=name,
        defaults=dict(shell="powershell", category="PatchGate", script_body=body, default_timeout=timeout,
                      description=desc),
    )
    script_ids[key] = script.pk

# 5. Tactical never auto-approves: every severity of the default patch policy = manual.
for p in WinUpdatePolicy.objects.filter(agent__isnull=True, policy__isnull=True):
    p.critical = p.important = p.moderate = p.low = p.other = "manual"
    p.save()

# 6. Agent enrollment token (what Tactical's "Install agent" dialog generates).
installer = User.objects.filter(is_installer_user=True).first()
_, install_token = AuthToken.objects.create(user=installer, expiry=dt.timedelta(hours=24))

print("PATCHGATE_PROVISION=" + json.dumps({
    "apiKey": api_key,
    "clientId": client.pk,
    "siteId": site.pk,
    **script_ids,
    "installToken": install_token,
}))
