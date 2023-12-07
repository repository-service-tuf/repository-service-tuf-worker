from securesystemslib.signer import Key, Signer


class SignerStore:
    """Generic signer store.

    Provides method to load and cache signer for passed public key, using a URI
    configured in a custom field of the passed key.

    """

    def __init__(self):
        self._signers: dict[str, Signer] = {}

    def get(self, key: Key) -> Signer:
        """Return signer for passed key.

        NOTE: the passed `key` is expected to have an "x-rstuf-online-key-uri"
        field in its `unrecognized_fields` attribute. This uri is used with the
        generic `Signer.from_priv_key_uri` interface, and, along with the
        public key, it encodes all information necessary to load the signer.

        Additional required information, e.g. to authenticate with a Cloud KMS,
        may be provided via signer type specific environment variables.

        """

        # If signer not in cache, load it using config
        if key.keyid not in self._signers:
            uri = key.unrecognized_fields["x-rstuf-online-key-uri"]
            self._signers[key.keyid] = Signer.from_priv_key_uri(uri, key)

        return self._signers[key.keyid]
