"""Shared agent bootstrap utilities."""
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(_REPO_ROOT / "saoe-core"))
sys.path.insert(0, str(_REPO_ROOT / "saoe-openclaw"))

from saoe_core.audit.events_sqlite import AuditLog
from saoe_core.crypto.age_vault import AgeVault
from saoe_core.crypto.keyring import hash_verify_key, load_signing_key, load_verify_key
from saoe_openclaw.shim import AgentShim


def load_config(demo_dir: Path | None = None) -> dict:
    if demo_dir is None:
        demo_dir = Path(__file__).parent.parent
    return json.loads((demo_dir / "demo_config.json").read_text())


def build_shim(agent_id: str, demo_dir: Path | None = None) -> AgentShim:
    """Construct an AgentShim for *agent_id* from the demo config."""
    config = load_config(demo_dir)

    keys_dir = Path(config["keys_dir"])
    vault_dir = Path(config["vault_dir"])
    queues_dir = Path(config["queues_dir"])
    quarantine_dir = Path(config["quarantine_dir"])

    # Load this agent's signing key
    sk = load_signing_key(keys_dir / "agents_private" / f"{agent_id}.key")

    # Load dispatcher verify key (for AgeVault pin)
    dispatcher_pin = config["dispatcher_pin"]

    # Build vault (real age vault)
    identity_file = Path(config["age_identity_file"])
    vault = AgeVault(vault_dir=vault_dir, identity_file=identity_file, dispatcher_pin=dispatcher_pin)

    # Load known sender keys (all agent public keys)
    known_sender_keys = {}
    agents_pub_dir = keys_dir / "agents_public"
    for pub_file in agents_pub_dir.glob("*.pub"):
        aid = pub_file.stem
        known_sender_keys[aid] = load_verify_key(pub_file)

    audit_log = AuditLog(Path(config["events_db"]))

    queue_dir = queues_dir / agent_id
    queue_dir.mkdir(parents=True, exist_ok=True)

    return AgentShim(
        agent_id=agent_id,
        vault=vault,
        audit_log=audit_log,
        signing_key=sk,
        known_sender_keys=known_sender_keys,
        queue_dir=queue_dir,
        quarantine_dir=quarantine_dir,
    )
