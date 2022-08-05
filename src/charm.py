#!/usr/bin/env python3
# Copyright 2021 Guillaume Belanger
# See LICENSE file for licensing details.

"""Charm that requests TLS certificates using the tls-certificates interface and stores them.

It doesn't do anything more than that.
Simply asking for certificates.
And storing them.
"""

import logging
import secrets
import string
from typing import Optional, Union

from charms.tls_certificates_interface.v1.tls_certificates import (  # type: ignore[import]
    CertificateAvailableEvent,
    CertificateExpiredEvent,
    CertificateExpiringEvent,
    CertificateRevokedEvent,
    TLSCertificatesRequiresV1,
    generate_csr,
    generate_private_key,
)
from ops.charm import CharmBase, ConfigChangedEvent, RelationJoinedEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus

logger = logging.getLogger(__name__)


class TLSRequirerOperatorCharm(CharmBase):
    """TLS Requirer Operator Charm."""

    def __init__(self, *args):
        """Handles events for certificate management."""
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)

        self.certificates = TLSCertificatesRequiresV1(self, "certificates")
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.certificates.on.certificate_expired, self._on_certificate_expiring
        )
        self.framework.observe(
            self.certificates.on.certificate_revoked, self._on_certificate_expiring
        )

    @property
    def _config_subject(self) -> Optional[str]:
        """Returns the user provided common name.

         This common name should only be used when the 'generate-self-signed-certificates' config
         is set to True.

        Returns:
            str: Common name
        """
        return self.model.config.get("subject", None)

    @staticmethod
    def _generate_password() -> str:
        """Generates a random 12 character password.

        Returns:
            str: Password
        """
        chars = string.ascii_letters + string.digits
        return "".join(secrets.choice(chars) for _ in range(12))

    def _on_install(self, event) -> None:
        if not self.unit.is_leader():
            return
        if not self._config_subject:
            self.unit.status = BlockedStatus("Config `subject` must be set.")
            return
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        self._generate_private_key()

    def _on_certificates_relation_joined(self, event: RelationJoinedEvent) -> None:
        if not self.unit.is_leader():
            return
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        private_key_password = replicas_relation.data[self.app].get("private_key_password")
        private_key = replicas_relation.data[self.app].get("private_key")
        if not private_key or not private_key_password:
            self.unit.status = WaitingStatus(
                "Waiting for private key and private key password to be set"
            )
            event.defer()
            return
        csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject="whatever",
        )
        self.certificates.request_certificate_creation(certificate_signing_request=csr)
        replicas_relation.data[self.app].update({"csr": csr.decode()})

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        if not self.unit.is_leader():
            return
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        replicas_relation.data[self.app].update({"certificate": event.certificate})
        replicas_relation.data[self.app].update({"ca": event.ca})
        replicas_relation.data[self.app].update({"chain": event.chain})
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Triggered once when the juju config is changed.

        Args:
            event (ConfigChangedEvent): Juju event.

        Returns:
            None
        """
        if not self._config_subject:
            self.unit.status = BlockedStatus("Config `subject` must be set.")
            return

    def _generate_private_key(self) -> None:
        """Generates root certificate to be used to sign certificates.

        Returns:
            None
        """
        replicas_relation = self.model.get_relation("replicas")
        private_key_password = self._generate_password()
        private_key = generate_private_key(password=private_key_password.encode())
        replicas_relation.data[self.app].update(  # type: ignore[union-attr]
            {
                "private_key_password": private_key_password,
                "private_key": private_key.decode(),
            }
        )
        logger.info("Private key generated and stored.")

    def _on_certificate_expiring(
        self,
        event: Union[CertificateExpiringEvent, CertificateExpiredEvent, CertificateRevokedEvent],
    ) -> None:
        if not self.unit.is_leader():
            return
        if not self._config_subject:
            self.unit.status = BlockedStatus("Config `subject` must be set.")
            return
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        self.unit.status = MaintenanceStatus("Requesting new certificate")
        old_csr = replicas_relation.data[self.app].get("csr")
        private_key_password = replicas_relation.data[self.app].get("private_key_password")
        private_key = replicas_relation.data[self.app].get("private_key")
        if not private_key or not private_key_password:
            self.unit.status = WaitingStatus(
                "Waiting for private key and private key password to be set"
            )
            return
        new_csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject=self._config_subject,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr, new_certificate_signing_request=new_csr
        )
        replicas_relation.data[self.app].update({"csr": new_csr.decode()})


if __name__ == "__main__":
    main(TLSRequirerOperatorCharm)
