from base64 import b64decode
from hashlib import blake2b
from pathlib import Path

from securesystemslib.signer import Key, SecretsHandler, Signer

from repository_service_tuf_worker import Dynaconf


class SignerStore:
    """Generic signer store.

    - Loads per-signer info (uri, secrets handler) from config on `init`.
    - Loads signer for pub key on `get`.

    FIXME: include keyid in signer config to map config to public keys
    """

    def __init__(self, settings: Dynaconf):
        self._signers: dict[str, Signer] = {}
        self._signer_infos: dict[str, tuple[str, SecretsHandler]]

        if settings.KEYVAULT_BACKEND == "LocalKeyVault":
            for signer_info in settings.LOCAL_KEYVAULT_KEYS.split(":"):
                keyid, uri, secrets_handler = self._parse_local(
                    signer_info, settings.LOCAL_KEYVAULT_PATH
                )

            self._signer_infos[keyid] = (uri, secrets_handler)

    @staticmethod
    def _parse_local(
        signer_info: str, signer_dir: str
    ) -> tuple[str, str, SecretsHandler]:
        """Parses keyid, uri and secrets handler from single signer info chunk.

        If chunk contains key data, it is written to a file.
        Colon-separated chunks can be found in RSTUF_LOCAL_KEYVAULT_KEYS.

        FIXME: encoding is overly complex, each chunk can be one of:
            1. path to key file , password, type (optional)
            2. base64 encoded key data, password, type (optional)
            3. path to a secret, which contains (1)

        I recommend to pick one good way to configure file-based keys only
        """
        # Case-handle signer_info is in a secret
        if signer_info.startswith("/run/secrets/"):
            with open(signer_info) as f:
                signer_info = f.read().rstrip("\n")

        # Unpack signer_info, ignore irrelevant optional 'keytype' (*_)
        # FIXME: 'keytype' in public key is authoritative, no need to config
        filename, password, *_ = signer_info.split(",")

        # Case-handle signer_info contains key data
        if filename.startswith("base64|"):
            key_data = b64decode(filename[len("base64|") :])
            filename = blake2b(key_data, digest_size=16)
            with open(Path(signer_dir) / filename, "wb") as f:
                f.write(key_data)

        # FIXME: we can't use this keyid because it does not map to a pubkey.
        keyid = filename

        path = f"{signer_dir}/{filename}"
        uri = f"file:{path}?encrypted=true"

        # FIXME: what is the benefit of using a 'password', which is passed
        # along with the secret key data?
        secrets_handler = lambda name: password

        return keyid, uri, secrets_handler

    def get(self, key: Key) -> Signer:
        """Return signer for passed key."""

        # If signer not in cache, load it using config
        if key.keyid not in self._signers:
            # FIXME: provide keyid mapping and use it here
            # uri, sec = self._signer_infos[key.keyid]
            uri, sec = self._signer_infos.values()[0]

            self._signers[key.keyid] = Signer.from_priv_key_uri(uri, key, sec)

        return self._signers[key.keyid]
