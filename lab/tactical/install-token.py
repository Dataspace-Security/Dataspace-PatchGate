# Runs INSIDE the Tactical backend (python manage.py shell < install-token.py).
# Creates ONLY a fresh 24 h agent enrollment token (what Tactical's "Install agent" dialog generates),
# without touching the API key the Bank A connector uses. Prints PATCHGATE_INSTALL_TOKEN=<json>.
import datetime as dt
import json

from knox.models import AuthToken

from accounts.models import User
from clients.models import Client, Site

installer = User.objects.filter(is_installer_user=True).first()
_, token = AuthToken.objects.create(user=installer, expiry=dt.timedelta(hours=24))
client = Client.objects.get(name="Lab Bank")
site = Site.objects.get(client=client, name="Branch-001 Pune")
expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=24)).isoformat()
print("PATCHGATE_INSTALL_TOKEN=" + json.dumps({"installToken": token, "clientId": client.pk, "siteId": site.pk, "expiresAt": expires}))
