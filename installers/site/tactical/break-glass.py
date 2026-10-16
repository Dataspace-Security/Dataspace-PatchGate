# Runs INSIDE the Tactical backend container:  python manage.py shell < /tmp/pg-break-glass.py
# Options from /tmp/pg-break-glass-args.json (written by install-site.sh --break-glass on|off):
#   {"state": "on" | "off" | "check", "by": "<who, from the site VM>"}
#
# Break-glass for the sealed site Tactical (RUNBOOK "Tactical is sealed"): the dashboard login of the
# break-glass account tacticaladmin is normally blocked (Tactical's per-user block_dashboard_login).
#   on  -> unblock it (emergency use of the Tactical dashboard)
#   off -> block it again and end its open dashboard sessions
#   check -> read-only sealed-state self-check (install-site.sh --status): prints PATCHGATE_SEAL_CHECK=<json>
# Every change is written to Tactical's audit log, which the PatchGate connector reports to PatchGate
# (TACTICAL_AUDIT_SYNC -> "Tactical activity", critical notification, bank audit chain / SIEM).
# Prints one line: PATCHGATE_BREAK_GLASS=<json>
import json

from django.db import models
from django.utils import timezone
from knox.models import AuthToken

from accounts.models import APIKey, User
from core.models import CoreSettings
from logs.models import AuditLog
from winupdate.models import WinUpdatePolicy

BREAK_GLASS_USER = "tacticaladmin"

with open("/tmp/pg-break-glass-args.json", encoding="utf-8") as f:
    args = json.load(f)
state = str(args.get("state", ""))
if state not in ("on", "off", "check"):
    raise SystemExit("state must be on, off or check")

if state == "check":
    now = timezone.now()
    svc = User.objects.filter(username="patchgate-svc").first()
    open_users = [u.username for u in User.objects.filter(is_installer_user=False, block_dashboard_login=False).exclude(username="patchgate-svc")]
    other_keys = APIKey.objects.filter(models.Q(expiration__isnull=True) | models.Q(expiration__gt=now))
    if svc is not None:
        other_keys = other_keys.exclude(user=svc)
    severities = ("critical", "important", "moderate", "low", "other")
    loose = sum(1 for p in WinUpdatePolicy.objects.all() if any(getattr(p, s) != "manual" for s in severities))
    core = CoreSettings.objects.first()
    print("PATCHGATE_SEAL_CHECK=" + json.dumps({
        "openDashboardUsers": ";".join(open_users),
        "otherValidApiKeys": other_keys.count(),
        "nonManualPatchPolicies": loose,
        "agentAutoUpdate": "on" if (core is not None and core.agent_auto_update) else "off",
        "svcBlocked": "yes" if (svc is not None and svc.block_dashboard_login) else "no",
        "svcAuditRead": "yes" if (svc is not None and svc.role is not None and svc.role.can_view_auditlogs) else "no",
    }))
    raise SystemExit(0)

by = str(args.get("by", "root"))[:80]

user = User.objects.get(username=BREAK_GLASS_USER)
blocked = state == "off"
User.objects.filter(pk=user.pk).update(block_dashboard_login=blocked)
if blocked:
    AuthToken.objects.filter(user=user).delete()  # end open dashboard sessions

AuditLog.objects.create(
    username="site-root (break-glass)",
    object_type="user",
    action="modify",
    message=("BREAK-GLASS %s: dashboard login of %s %s by root on the site VM (%s)"
             % (state.upper(), BREAK_GLASS_USER, "blocked again" if blocked else "UNBLOCKED", by))[:255],
    debug_info={"source": "install-site.sh --break-glass %s" % state},
)

print("PATCHGATE_BREAK_GLASS=" + json.dumps({"state": state, "user": BREAK_GLASS_USER}))
