import logging
from pathlib import Path

LOG_FILE = Path(__file__).parent.parent / "logs" / "auth.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

logger = logging.getLogger("authenticator")

def log_auth_event(
    username,
    source_ip,
    result,
    reason
):
    logger.info(
        f"username={username} "
        f"source_ip={source_ip} "
        f"result={result} "
        f"reason={reason} "
    )
