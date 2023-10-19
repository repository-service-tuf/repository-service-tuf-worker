import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from securesystemslib.exceptions import UnsupportedAlgorithmError
from securesystemslib.signer import KEY_FOR_TYPE_AND_SCHEME, AWSSigner, Key

from repository_service_tuf_worker.interfaces import (
    Dynaconf,
    IKeyVault,
    KeyVaultError,
    ServiceSettings,
)
from repository_service_tuf_worker import parse_raw_key

# We calculate the supported signing algorithms as more could be added.
SUPPORTED_SIGNING_ALGORITHMS: List[str] = []
ALGORITHM_TO_SCHEME: Dict[str, str] = {}

for alg_info in KEY_FOR_TYPE_AND_SCHEME.keys():
    key_scheme = alg_info[1]
    try:
        AWSSigner._get_keytype_for_scheme(key_scheme)
        aws_alg_name = AWSSigner._get_aws_signing_algo(key_scheme)
        SUPPORTED_SIGNING_ALGORITHMS.append(aws_alg_name)
        ALGORITHM_TO_SCHEME[aws_alg_name] = key_scheme
    except KeyError:
        continue


@dataclass
class AWSKey:
    awskms_id: str
    # "rsassa-pss-sha256: scheme is the one equal to the default
    # "RSASSA_PSS_SHA_256" signing algorithm
    key_scheme: Optional[str] = "rsassa-pss-sha256"


class AWSKMS(IKeyVault):
    """AWSKMS KeyVault type"""

    def __init__(self, signers: AWSSigner):
        """Configuration class for RSTUF Worker AWSKMS service.
        Manages all settings related to the usage of the online key(s).

        Args:
            signer: List of possible AWSSigners to be used
        """
        self._signers: List[AWSSigner] = signers

    @classmethod
    def _raw_key_parser(cls, keys: str) -> List[AWSKey]:
        """
        Parses the key(s) given in the `RSTUF_AWSKMS_KEYVAULT_KEYS` and returns
        as `AWSKey` object(s).
        """
        parsed_keys: List[AWSKey] = []
        for raw_key in keys.split(":"):
            key_data = parse_raw_key(raw_key)

            if len(key_data) == 2:  # awskms_id,signing_algorithm
                awskms_id = key_data[0]
                signing_algorithm = key_data[1]
                key_scheme = ALGORITHM_TO_SCHEME[signing_algorithm]
                parsed_keys.append(AWSKey(awskms_id, key_scheme))

            elif len(key_data) == 1:  # awskms_id
                parsed_keys.append(AWSKey(key_data[0]))

            else:
                logging.error(f"Key {raw_key} is invalid")
                pass

        if len(parsed_keys) == 0:
            raise KeyVaultError(
                "No valid keys in configuration 'RSTUF_AWSKMS_KEYVAULT_KEYS'"
            )

        return parsed_keys

    @staticmethod
    def _init_signers_from_valid_keys(keys: List[AWSKey]) -> List[AWSSigner]:
        try:
            from botocore.exceptions import BotoCoreError, ClientError
        except ModuleNotFoundError:
            err_msg = "botocore is required by AWSKMS - 'pip install botocore'"
            raise ModuleNotFoundError(err_msg)

        signers: List[AWSSigner] = []
        for aws_key in keys:
            id = aws_key.awskms_id
            try:
                priv_key_uri, public_key = AWSSigner.import_(
                    aws_key.awskms_id, aws_key.key_scheme
                )
                signer = AWSSigner.from_priv_key_uri(priv_key_uri, public_key)
                signer.sign(b"test data")
                signers.append(signer)
                logging.info(f"Signer from key {id} created")
            except (
                UnsupportedAlgorithmError,
                BotoCoreError,
                ClientError,
            ) as e:
                logging.error(str(e))
                logging.warning(f"Failed to load {id} AWSKMS key")

        if len(signers) == 0:
            raise KeyVaultError("No valid keys found in the AWSKMS")

        return signers

    @classmethod
    def configure(cls, settings: Dynaconf) -> None:
        """
        Run actions to check and configure the service using the settings.
        """
        # Setup official AWS env names which will be used from boto3.
        # See: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html#using-environment-variables  # noqa
        # We are limited on securesystemslib as they don't allow custom args.
        os.environ["AWS_ACCESS_KEY_ID"] = settings.AWSKMS_KEYVAULT_ACCESS_KEY
        secret_key_boto3_name = "AWS_SECRET_ACCESS_KEY"
        os.environ[secret_key_boto3_name] = settings.AWSKMS_KEYVAULT_SECRET_KEY
        region = settings.get("AWSKMS_KEYVAULT_REGION")
        if region is not None:
            os.environ["AWS_DEFAULT_REGION"] = region

        endpoint_url = settings.get("AWSKMS_KEYVAULT_ENDPOINT_URL")
        if endpoint_url is not None:
            os.environ["AWS_ENDPOINT_URL"] = endpoint_url

        logging.info(f"RSTUF KEYS: {settings.AWSKMS_KEYVAULT_KEYS}")
        keys = AWSKMS._raw_key_parser(settings.AWSKMS_KEYVAULT_KEYS)
        return cls(AWSKMS._init_signers_from_valid_keys(keys))

    @classmethod
    def settings(cls) -> List[ServiceSettings]:
        """Define the settings parameters."""
        return [
            ServiceSettings(
                names=["AWSKMS_KEYVAULT_KEYS"],
                required=True,
            ),
            ServiceSettings(
                names=["AWSKMS_KEYVAULT_ACCESS_KEY"],
                required=True,
            ),
            ServiceSettings(
                names=["AWSKMS_KEYVAULT_SECRET_KEY"],
                required=True,
            ),
            ServiceSettings(
                names=["AWSKMS_KEYVAULT_REGION"],
                required=False,
            ),
            ServiceSettings(
                names=["AWSKMS_KEYVAULT_ENDPOINT_URL"],
                required=False,
            ),
        ]

    def get(self, public_key: Key) -> AWSSigner:
        """Return a signer using the online key."""
        # TODO: update docs how to rotate the online key:
        # https://github.com/repository-service-tuf/repository-service-tuf/issues/527
        for signer in self._signers:
            if signer.public_key.keyid == public_key.keyid:
                return signer

        e = "Online key in root doesn't match any of the keys used by keyvault"
        raise KeyVaultError(e)
