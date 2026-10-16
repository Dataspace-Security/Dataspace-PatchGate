# LAB ONLY — runs INSIDE the lab Tactical backend:  python manage.py shell < /tmp/pg-sim-agent.py
# Simulates one bank PC in Tactical (no real Windows PC in this lab): an Agent row in site "Branch-001 Pune"
# with three Windows updates, so PatchGate's sync, COLLECT and the connector's real-time guard have something
# to read. Options in /tmp/pg-sim-agent-args.json: {"op": "create"|"approve"|"status"|"remove", "kb": "KB..."}
#   approve = what a human with the Tactical dashboard would do (agent -> Patches -> Approve). Tactical 1.5 does
#             not audit approvals; the guard finds them by reading /agents/ + /winupdate/<agent>/.
# Prints one line: PATCHGATE_SIM=<json>
import json
import uuid

from django.utils import timezone

from agents.models import Agent
from clients.models import Site
from winupdate.models import WinUpdate

HOSTNAME = "LAB-SIM-PC01"
UPDATES = [
    ("KB5034441", "2024-01 Security Update for Windows 11 (KB5034441)", "Critical"),
    ("KB890830", "Windows Malicious Software Removal Tool x64 - v5.120 (KB890830)", "Moderate"),
    ("KB2267602", "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602", "Important"),
]

with open("/tmp/pg-sim-agent-args.json", encoding="utf-8") as f:
    args = json.load(f)
op = args.get("op")
agent = Agent.objects.filter(hostname=HOSTNAME).first()

if op == "create":
    if agent is None:
        site = Site.objects.get(client__name="Lab Bank", name="Branch-001 Pune")
        agent = Agent.objects.create(
            hostname=HOSTNAME,
            agent_id="LabSim" + uuid.uuid4().hex,
            site=site,
            version="2.10.0",
            plat="windows",
            goarch="amd64",
            monitoring_type="workstation",
            operating_system="Windows 11 Pro, 64 bit v23H2 (build 22631.3007)",
            last_seen=timezone.now(),
            boot_time=(timezone.now() - timezone.timedelta(hours=5)).timestamp(),
            total_ram=16,
            public_ip="10.231.60.11",
        )
    else:
        Agent.objects.filter(pk=agent.pk).update(last_seen=timezone.now())
    for kb, title, sev in UPDATES:
        WinUpdate.objects.get_or_create(
            agent=agent, kb=kb,
            defaults={"guid": str(uuid.uuid5(uuid.NAMESPACE_URL, "patchgate-lab/" + kb)), "title": title,
                      "severity": sev, "action": "nothing", "installed": False, "downloaded": False},
        )
elif op == "approve":
    if agent is None:
        raise SystemExit("no simulated agent (op=create first)")
    WinUpdate.objects.filter(agent=agent, kb=args["kb"]).update(action="approve")
elif op == "remove":
    if agent is not None:
        agent.delete()
        agent = None
elif op != "status":
    raise SystemExit("op must be create, approve, status or remove")

updates = [] if agent is None else [
    {"kb": u.kb, "action": u.action, "guid": u.guid} for u in WinUpdate.objects.filter(agent=agent).order_by("kb")
]
print("PATCHGATE_SIM=" + json.dumps({"hostname": HOSTNAME if agent else None,
                                     "agentId": agent.agent_id if agent else None, "updates": updates}))
