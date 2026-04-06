import os
import requests
from ..config import settings
from ..utils import get_logger


logger = get_logger(__name__)


def download_keys():
    """
    Downloads the keys from the supabase storage.
    """
    try:
        public_key_path = "keys/public.pem"
        private_key_path = "keys/private.pem"

        if not os.path.exists("keys"):
            os.makedirs("keys")

        headers = {
            "apikey": settings.supabase_key,
        }
        public_key_response = requests.get(
            f"{settings.supabase_url}/storage/v1/object/authenticated/{settings.bucket_name}/{public_key_path}",
            headers=headers,
            stream=True,
        )

        if public_key_response.status_code != 200:
            logger.error(
                f"Failed to download public key. Status code: {public_key_response.status_code}"
            )
            raise RuntimeError("Failed to download public key")

        with open(public_key_path, "wb") as file:
            for chunk in public_key_response.iter_content(chunk_size=8192):
                file.write(chunk)

        logger.info(
            f"Public key downloaded successfully and saved as '{public_key_path}'"
        )

        private_key_response = requests.get(
            f"{settings.supabase_url}/storage/v1/object/authenticated/{settings.bucket_name}/{private_key_path}",
            headers=headers,
            stream=True,
        )

        if private_key_response.status_code != 200:
            logger.error(
                f"Failed to download private key. Status code: {private_key_response.status_code}"
            )
            raise RuntimeError("Failed to download private key")

        with open(private_key_path, "wb") as file:
            for chunk in private_key_response.iter_content(chunk_size=8192):
                file.write(chunk)

        logger.info(
            f"Private key downloaded successfully and saved as '{private_key_path}'"
        )
    except Exception:
        logger.exception("Error downloading keys")
        raise RuntimeError("Failed to download keys") from None
