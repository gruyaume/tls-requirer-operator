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
from ops.charm import (
    ActionEvent,
    CharmBase,
    ConfigChangedEvent,
    RelationCreatedEvent,
    RelationJoinedEvent,
)
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus

logger = logging.getLogger(__name__)


class TLSRequirerOperatorCharm(CharmBase):
    """TLS Requirer Operator Charm."""

    def __init__(self, *args):
        """Handles events for certificate management."""
        super().__init__(*args)
        self.certificates = TLSCertificatesRequiresV1(self, "certificates")
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)
        self.framework.observe(self.on.renew_certificate_action, self._on_renew_certificate_action)
        self.framework.observe(
            self.on.revoke_certificate_action,
            self._on_revoke_certificate_action,
        )
        self.framework.observe(
            self.on.show_certificates_relation_data_action,
            self._on_show_certificates_relation_data_action,
        )
        self.framework.observe(
            self.on.replicas_relation_created, self._on_replicas_relation_created
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

    @property
    def _private_key_is_stored(self) -> bool:
        if not self._replicas_relation_created:
            logger.info("Replicas relation not created")
            return False
        replicas_relation = self.model.get_relation("replicas")
        private_key_password = replicas_relation.data[self.app].get("private_key_password")  # type: ignore[union-attr]  # noqa: E501
        private_key = replicas_relation.data[self.app].get("private_key")  # type: ignore[union-attr]  # noqa: E501
        if private_key and private_key_password:
            return True
        else:
            logger.info("Private key and password are not stored")
            return False

    @property
    def _replicas_relation_created(self) -> bool:
        return self._relation_created("replicas")

    @property
    def _certificates_relation_created(self) -> bool:
        return self._relation_created("certificates")

    @property
    def _csr_is_stored(self) -> bool:
        replicas_relation = self.model.get_relation("replicas")
        old_csr = replicas_relation.data[self.app].get("csr")  # type: ignore[union-attr]
        if not old_csr:
            return False
        return True

    @staticmethod
    def _generate_password() -> str:
        """Generates a random 12 character password.

        Returns:
            str: Password
        """
        chars = string.ascii_letters + string.digits
        return "".join(secrets.choice(chars) for _ in range(12))

    def _on_replicas_relation_created(self, event: RelationCreatedEvent) -> None:
        """Triggered when peer relation is created.

        Generates and stores a private key on

        Args:
            event: Juju event.

        Returns:
            None
        """
        if not self.unit.is_leader():
            return
        self._generate_private_key()

    def _on_certificates_relation_joined(self, event: RelationJoinedEvent) -> None:
        if not self.unit.is_leader():
            return
        if not self._config_subject:
            self.unit.status = BlockedStatus("Config `subject` must be set.")
            return
        if not self._private_key_is_stored:
            self.unit.status = WaitingStatus("Waiting for private key to be generated.")
            event.defer()
            return
        self._request_certificate()

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
        logger.info(f"New certificate is stored: {event.certificate}")
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Triggered once when the juju config is changed.

        Args:
            event (ConfigChangedEvent): Juju event.

        Returns:
            None
        """
        if not self.unit.is_leader():
            return
        if not self._config_subject:
            self.unit.status = BlockedStatus("Config `subject` must be set.")
            return
        if not self._private_key_is_stored:
            self.unit.status = WaitingStatus("Waiting for private key to be generated.")
            return
        if not self._certificates_relation_created:
            self.unit.status = BlockedStatus(
                "Waiting for `tls-certificates` relation to be created"
            )
            return
        self._request_certificate()

    def _request_certificate(self) -> None:
        """Requests TLS certificates.

        Returns:
            None
        """
        replicas_relation = self.model.get_relation("replicas")
        private_key_password = replicas_relation.data[self.app].get(  # type: ignore[union-attr]
            "private_key_password"
        )
        private_key = replicas_relation.data[self.app].get(  # type: ignore[union-attr]
            "private_key"
        )
        csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject=self._config_subject,
        )
        self.certificates.request_certificate_creation(certificate_signing_request=csr)
        replicas_relation.data[self.app].update({"csr": csr.decode()})  # type: ignore[union-attr]
        self.unit.status = MaintenanceStatus("Requesting new certificate")

    def _renew_certificate(self) -> None:
        replicas_relation = self.model.get_relation("replicas")
        old_csr = replicas_relation.data[self.app].get("csr")  # type: ignore[union-attr]
        private_key_password = replicas_relation.data[self.app].get(  # type: ignore[union-attr]
            "private_key_password"
        )
        private_key = replicas_relation.data[self.app].get(  # type: ignore[union-attr]
            "private_key"
        )
        self.unit.status = MaintenanceStatus("Requesting new certificate")
        new_csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject=self._config_subject,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr.encode(),
            new_certificate_signing_request=new_csr,
        )
        replicas_relation.data[self.app].update(  # type: ignore[union-attr]
            {"csr": new_csr.decode()}
        )
        self.unit.status = MaintenanceStatus("Requesting new certificate")

    def _relation_created(self, relation_name: str) -> bool:
        """Returns whether given relation was created.

        Args:
            relation_name (str): Relation name

        Returns:
            bool: True/False
        """
        try:
            if self.model.get_relation(relation_name):
                return True
            return False
        except KeyError:
            return False

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
        """Triggered on various certificate expiring/revoked events.

        Args:
            event: Juju event

        Returns:
            None
        """
        if not self.unit.is_leader():
            return
        if not self._config_subject:
            self.unit.status = BlockedStatus("Config `subject` must be set.")
            return
        if not self._private_key_is_stored:
            self.unit.status = WaitingStatus("Waiting for private key to be generated.")
            event.defer()
            return
        replicas_relation = self.model.get_relation("replicas")
        if not self._csr_is_stored:
            self.unit.status = BlockedStatus("Old CSR not found")
            return
        old_csr = replicas_relation.data[self.app].get("csr")  # type: ignore[union-attr]
        private_key_password = replicas_relation.data[self.app].get("private_key_password")  # type: ignore[union-attr]  # noqa: E501
        private_key = replicas_relation.data[self.app].get("private_key")  # type: ignore[union-attr]  # noqa: E501
        self.unit.status = MaintenanceStatus("Requesting new certificate")
        new_csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject=self._config_subject,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr.encode(),
            new_certificate_signing_request=new_csr,
        )
        replicas_relation.data[self.app].update({"csr": new_csr.decode()})  # type: ignore[union-attr]  # noqa: E501

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `get-certificate` Juju action.

        Args:
            event: Juju event

        Returns:
            None
        """
        replicas_relation = self.model.get_relation("replicas")
        if replicas_relation:
            certificate = replicas_relation.data[self.app].get("certificate", None)
            ca = replicas_relation.data[self.app].get("ca", None)
            chain = replicas_relation.data[self.app].get("chain", None)
        else:
            certificate = None
            ca = None
            chain = None
        if not certificate:
            event.fail("Certificate not available")
            return
        event.set_results(
            {
                "certificate": certificate,
                "ca": ca,
                "chain": chain,
            }
        )

    def _on_renew_certificate_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `renew-certificate` Juju action.

        Args:
            event: Juju event

        Returns:
            None
        """
        if not self.unit.is_leader():
            event.fail("Unit is not leader")
            return
        if not self._private_key_is_stored:
            event.fail("Private key is not stored")
            return
        replicas_relation = self.model.get_relation("replicas")
        old_csr = replicas_relation.data[self.app].get("csr")  # type: ignore[union-attr]
        if old_csr:
            self._renew_certificate()
        else:
            self._request_certificate()
        event.set_results(
            {
                "success": "Certificate renewal sent successfully",
            }
        )

    def _on_revoke_certificate_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `revoke-certificate` Juju action.

        Args:
            event: Juju event

        Returns:
            None
        """
        if not self.unit.is_leader():
            event.fail("Unit is not leader")
            return
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            event.fail("No replicas relation")
            return
        csr = replicas_relation.data[self.app].get("csr")
        if not csr:
            event.fail("No stored CSR")
            return
        certificate = replicas_relation.data[self.app].get("certificate")
        if not certificate:
            event.fail("No stored certificate")
            return
        self.certificates.request_certificate_revocation(certificate_signing_request=csr.encode())
        replicas_relation.data[self.app].pop("certificate")
        replicas_relation.data[self.app].pop("ca")
        replicas_relation.data[self.app].pop("chain")
        event.set_results(
            {
                "success": "Certificate revocation sent.",
            }
        )

    def _on_show_certificates_relation_data_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `show-certificates-relation` Juju action.

        Args:
            event: Juju event

        Returns:
            None
        """
        certificates_relation = self.model.get_relation("certificates")
        if not certificates_relation:
            event.fail("No certificates relation")
            return
        event.set_results(
            {
                "relation-data": str(certificates_relation.data),
            }
        )


if __name__ == "__main__":
    main(TLSRequirerOperatorCharm)
