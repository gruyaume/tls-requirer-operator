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
    InstallEvent,
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
        self.framework.observe(self.on.install, self._on_install)
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
    def _replicas_relation_created(self) -> bool:
        return self._relation_created("replicas")

    @property
    def _certificates_relation_created(self) -> bool:
        return self._relation_created("certificates")

    @staticmethod
    def _generate_password() -> str:
        """Generates a random 12 character password.

        Returns:
            str: Password
        """
        chars = string.ascii_letters + string.digits
        return "".join(secrets.choice(chars) for _ in range(12))

    @property
    def _stored_private_key_password(self) -> Optional[str]:
        return self._get_item_from_peer_relation_data(key="private_key_password")

    @property
    def _stored_private_key(self) -> Optional[str]:
        return self._get_item_from_peer_relation_data(key="private_key")

    @property
    def _stored_csr(self) -> Optional[str]:
        return self._get_item_from_peer_relation_data(key="csr")

    @property
    def _stored_certificate(self) -> Optional[str]:
        return self._get_item_from_peer_relation_data(key="certificate")

    @property
    def _stored_ca_certificate(self) -> Optional[str]:
        return self._get_item_from_peer_relation_data(key="ca")

    @property
    def _stored_ca_chain(self) -> Optional[str]:
        return self._get_item_from_peer_relation_data(key="chain")

    def _store_private_key(self, private_key: str) -> None:
        self._store_item(key="private_key", value=private_key)

    def _store_private_key_password(self, private_key_password: str) -> None:
        self._store_item(key="private_key_password", value=private_key_password)

    def _store_certificate(self, certificate: str) -> None:
        self._store_item(key="certificate", value=certificate)

    def _store_ca_certificate(self, certificate: str) -> None:
        self._store_item(key="ca", value=certificate)

    def _store_ca_chain(self, chain: str) -> None:
        self._store_item(key="chain", value=chain)

    def _store_csr(self, csr: str) -> None:
        self._store_item(key="csr", value=csr)

    def _store_item(self, key: str, value: str) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            raise RuntimeError("Peer relation not created")
        replicas_relation.data[self.unit].update({key: value})

    def _unstore_certificate(self) -> None:
        self._unstore_item("certificate")

    def _unstore_ca_certificate(self) -> None:
        self._unstore_item("ca")

    def _unstore_ca_chain(self) -> None:
        self._unstore_item("chain")

    def _unstore_item(self, key: str) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            raise RuntimeError("Peer relation not created")
        replicas_relation.data[self.unit].pop(key)

    def _get_item_from_peer_relation_data(self, key: str) -> Optional[str]:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            raise RuntimeError("Peer relation not created")
        return replicas_relation.data[self.unit].get(key, None)

    def _on_install(self, event: InstallEvent) -> None:
        """Triggered when install event.

        Generates and stores a private key.

        Args:
            event: Juju event.

        Returns:
            None
        """
        if not self._replicas_relation_created:
            self.unit.status = WaitingStatus("Waiting for replicas relation to be created")
            event.defer()
            return
        self._generate_private_key()

    def _on_certificates_relation_joined(self, event: RelationJoinedEvent) -> None:
        if not self._config_subject:
            self.unit.status = BlockedStatus("Config `subject` must be set")
            return
        if not self._replicas_relation_created:
            self.unit.status = WaitingStatus("Waiting for replicas relation to be created")
            event.defer()
            return
        if not self._stored_private_key or not self._stored_private_key_password:
            self.unit.status = WaitingStatus(
                "Waiting for private key and password to be generated"
            )
            event.defer()
            return
        self._request_certificate()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        self._store_certificate(event.certificate)
        self._store_ca_certificate(event.ca)
        self._store_ca_chain(event.chain)
        logger.info(f"New certificate is stored: {event.certificate}")
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
        if not self._replicas_relation_created:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created.")
            event.defer()
            return
        if not self._stored_private_key or not self._stored_private_key_password:
            self.unit.status = WaitingStatus(
                "Waiting for private key and password to be generated."
            )
            event.defer()
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
        if not self._stored_private_key or not self._stored_private_key_password:
            raise RuntimeError("Private key or password not stored.")
        csr = generate_csr(
            private_key=self._stored_private_key.encode(),
            private_key_password=self._stored_private_key_password.encode(),
            subject=self._config_subject,
        )
        self.certificates.request_certificate_creation(certificate_signing_request=csr)
        self._store_csr(csr.decode())
        self.unit.status = MaintenanceStatus("Requesting new certificate")

    def _renew_certificate(self) -> None:
        if not self._stored_private_key or not self._stored_private_key_password:
            raise RuntimeError("Private key or password not stored.")
        if not self._stored_csr:
            raise RuntimeError("Old CSR not stored.")
        self.unit.status = MaintenanceStatus("Requesting new certificate")
        new_csr = generate_csr(
            private_key=self._stored_private_key.encode(),
            private_key_password=self._stored_private_key_password.encode(),
            subject=self._config_subject,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=self._stored_csr.encode(),
            new_certificate_signing_request=new_csr,
        )
        self._store_csr(csr=new_csr.decode())
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
        private_key_password = self._generate_password()
        private_key = generate_private_key(password=private_key_password.encode())
        self._store_private_key(private_key.decode())
        self._store_private_key_password(private_key_password)
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
        if not self._config_subject:
            self.unit.status = BlockedStatus("Config `subject` must be set.")
            return
        if not self._replicas_relation_created:
            self.unit.status = WaitingStatus("Waiting for replicas relation to be created")
            event.defer()
            return
        if not self._stored_private_key or not self._stored_private_key_password:
            self.unit.status = WaitingStatus("Waiting for private key to be generated.")
            event.defer()
            return
        if not self._stored_csr:
            self.unit.status = BlockedStatus("Old CSR not found")
            return
        self.unit.status = MaintenanceStatus("Requesting new certificate")
        new_csr = generate_csr(
            private_key=self._stored_private_key.encode(),
            private_key_password=self._stored_private_key_password.encode(),
            subject=self._config_subject,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=self._stored_csr.encode(),
            new_certificate_signing_request=new_csr,
        )
        self._store_csr(csr=new_csr.decode())

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `get-certificate` Juju action.

        Args:
            event: Juju event

        Returns:
            None
        """
        if not self._replicas_relation_created:
            event.fail("Replicas relation not created.")
            return
        if self._stored_certificate:
            event.set_results(
                {
                    "certificate": self._stored_certificate,
                    "ca": self._stored_ca_certificate,
                    "chain": self._stored_ca_chain,
                }
            )
        else:
            event.fail("Certificate not available")

    def _on_renew_certificate_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `renew-certificate` Juju action.

        Args:
            event: Juju event

        Returns:
            None
        """
        if not self._stored_private_key or not self._stored_private_key_password:
            event.fail("Private key or password is not stored")
            return
        if self._stored_csr:
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
        if not self._replicas_relation_created:
            event.fail("No replicas relation")
            return
        if not self._stored_csr:
            event.fail("No stored CSR")
            return
        if not self._stored_certificate:
            event.fail("No stored certificate")
            return
        self.certificates.request_certificate_revocation(
            certificate_signing_request=self._stored_csr.encode()
        )
        self._unstore_certificate()
        self._unstore_ca_certificate()
        self._unstore_ca_chain()
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
