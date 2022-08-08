# Copyright 2021 Guillaume Belanger
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from charm import TLSRequirerOperatorCharm

testing.SIMULATE_CAN_CONNECT = True

CHARM_LIB_PATH = "charms.tls_certificates_interface.v1.tls_certificates"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,7CA169096B30CA41F9561EE2CA0009CA\n\nOGRJ8PtVU7AInAI0JqChzHMOly6kDgSs4qAx1I5LBNSWrcO3lk73Z2OrTZ0CtfDR\nFNlAXZC2ukhVIUjF1e+duE8d3CMmtSHDSvGm81zpbtuvCIscnAUdDY5FeP0jxaXT\nq7re+vDHIjkJ9dU2TRqYZ5Z/2dLJRXn/7BUTZgb/Gceot++GgTBgkzK8GIllmhyC\nkbtmBxvU3Mnc+lB+FhvPeOgUvGx2suVCshvwsws52B9sguH2xRMhChJvfnSWu+EC\n+c43Ed+ZUAMuYLLIOd55SO+1ARf9wbb41cuMwYzmPGT18+L0WWiV2kf9c1Nmp4Ai\nchSAdIyc3npAqn78TGmCAdTiIyMfQNGuDXxo37uuRWm/E48TgVfZucoJaMQ3oFL/\ngXNFmi5FlS8BqEmC5UzvsYLWpY5Yh39XNazV5epR6W6YKVXYGhRWPjlDvjub7sOS\nYfDii03dK9E7Ju+jatmahYA95b5EuQLuT8JIcHjaB4PCdsspjM5sM1meZa6hp5IM\nrBewercgdGelBzszT5iV2dwjQh0M7iOr6kz8wxXsrJQDjLrqGOxAvuv+KZU9nwgr\nN+IvMtL0RnKnsRfwrwYF31OhrbHBIS8IMtIilX620lntEtXA7Vbth2TzpVOAgdEj\nWTIsA+fIzMbTx1uG7KJw6XJpJpsH3Cr+1bSl6sLEwClIeSQL69y2kmFosjaFbwzK\nwFMVZjoGu/IJP5WvN5oVS5ibWbUtXGprRtjFcHvjPL40MoEue8Q6IKeLFIB2amwK\n9JHkKNXRjubr8MVKUyaF57DF+y77ctkIHrBIcoGBXwXx1mZu6Xd1af7tEdl+LlpB\n/2tcwTO3uUCjRMHChrVwh/6YkzWQSislgIdf4famH8rvR5W+QXSb2NxUkmq9UMFz\nbknuR9oCCCdmwH4eC5g+LhU5Yar69nvehvzScrOQCrKRtYsmCRgwDY/ErqM01Jkg\npOCUyYcTn6SopOGU54ykHILJf611njNfkMScEznXwi1fvuYD/2+qNiVLwvRfDReC\nxkbvAD/hBJW0DOaLf+1P6PNe7+hL9KPNsv5bIyP/5Dok6Ns75GEI6UJFXkVp1fqt\nJCkPCtEUvEgDUrPbSX0vZSIlTgMkfv7ln+OiKpyHJ6EuH3JDgcRP+84VlPIkx91W\nKkOhqvoNkOz08IPzA7xbt0jGyDgMLh8Ob3tPLUpRaiPXg9Or646o3Z/i/FNocQzL\ndBVzLSZkCGfmeeXszjS/di7Kl2ilEJOMkJVX4H5j+GJ4i4kkXHUwDLL8FjfJggmI\nzW+Lxo7RyhCUhS8qgusdmqxBS7d7tPszqGksoylbgYwG5PW377LTRf9IUPfWM938\nWiyDgtrGAnVWmouni5Cqa8q2W1DZkMuc7JjdFwaYiSYTu5skG2fAUCBcR2/BWPPn\nRI86PXR8RHYgKO3IV+TyvxyEIwO654La95kCGk9tVSqY0kBguDiUnA6XlKuiK+y6\nFU9dEnaZf6z8e+0juiPGMWHW4vwmxirahchGozgpe7hI1DByiSi2bVyAF3TtcTYO\n9sfXiiHuu4GTmcuLauK7JKL1faQAKrSJl3SkLbYVcBsfTv9bcpfOves8EHuPhFPO\n-----END RSA PRIVATE KEY-----\n"  # noqa: E501
PRIVATE_KEY_PASSWORD = b"banana"


class TestCharm(unittest.TestCase):
    @staticmethod
    def get_certificate_from_file(filename: str) -> str:
        with open(filename, "r") as file:
            certificate = file.read()
        return certificate

    def setUp(self):
        self.harness = testing.Harness(TLSRequirerOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_unit_is_leader_when_replicas_relation_created_then_private_key_is_generated(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(key_values={"subject": "whatever"})

        relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="replicas/0")

        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        serialization.load_pem_private_key(
            data=relation_data["private_key"].encode(),
            password=relation_data["private_key_password"].encode(),
        )

    def test_given_unit_is_not_leader_when_replicas_relation_created_then_private_key_is_generated(
        self,
    ):
        self.harness.set_leader(is_leader=False)
        self.harness.update_config(key_values={"subject": "whatever"})

        relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="replicas/0")

        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )
        assert "private_key" not in relation_data
        assert "private_key_password" not in relation_data

    @patch("charm.generate_csr")
    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_creation")
    def test_given_unit_is_not_leader_and_private_key_is_stored_when_on_certificates_relation_joined_then_certificate_request_is_not_made(  # noqa: E501
        self, patch_request_certificate, patch_generate_csr
    ):
        self.harness.update_config(key_values={"subject": "whatever"})
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        key_values = {
            "private_key": PRIVATE_KEY,
            "private_key_password": PRIVATE_KEY_PASSWORD.decode(),
        }
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values=key_values,
        )
        event = Mock()
        csr = b"whatever csr"
        patch_generate_csr.return_value = csr

        self.harness.charm._on_certificates_relation_joined(event=event)

        patch_request_certificate.assert_not_called()

    @patch("charm.generate_csr")
    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_creation")
    def test_given_unit_is_leader_and_peer_relation_is_not_set_when_on_certificates_relation_joined_then_certificate_request_is_not_made(  # noqa: E501
        self, patch_request_certificate, patch_generate_csr
    ):
        self.harness.update_config(key_values={"subject": "whatever"})
        self.harness.set_leader(is_leader=True)
        event = Mock()
        patch_generate_csr.return_value = b"whatever csr"

        self.harness.charm._on_certificates_relation_joined(event=event)

        patch_request_certificate.assert_not_called()

    @patch("charm.generate_csr")
    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_creation")
    def test_given_unit_is_leader_and_peer_relation_is_set_but_private_key_not_stored_when_on_certificates_relation_joined_then_certificate_request_is_not_made(  # noqa: E501
        self, patch_request_certificate, patch_generate_csr
    ):
        self.harness.update_config(key_values={"subject": "whatever"})
        self.harness.set_leader(is_leader=True)
        event = Mock()
        patch_generate_csr.return_value = b"whatever csr"
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={"private_key_password": None, "private_key": None},
        )

        self.harness.charm._on_certificates_relation_joined(event=event)

        patch_request_certificate.assert_not_called()

    @patch("charm.generate_csr")
    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_creation")
    def test_given_unit_is_leader_and_private_key_is_stored_when_on_certificates_relation_joined_then_certificate_request_is_made(  # noqa: E501
        self, patch_request_certificate, patch_generate_csr
    ):
        self.harness.update_config(key_values={"subject": "whatever"})
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        key_values = {
            "private_key": PRIVATE_KEY,
            "private_key_password": PRIVATE_KEY_PASSWORD.decode(),
        }
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values=key_values,
        )
        event = Mock()
        csr = b"whatever csr"
        patch_generate_csr.return_value = csr

        self.harness.charm._on_certificates_relation_joined(event=event)

        patch_request_certificate.assert_called_with(certificate_signing_request=csr)

    @patch("charm.generate_csr")
    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_creation")
    def test_given_unit_is_leader_and_private_key_is_stored_when_on_certificates_relation_joined_then_csr_is_added_to_relation_data(  # noqa: E501
        self, _, patch_generate_csr
    ):
        self.harness.update_config(key_values={"subject": "whatever"})
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "private_key": PRIVATE_KEY,
                "private_key_password": PRIVATE_KEY_PASSWORD.decode(),
            },
        )
        event = Mock()
        csr = b"whatever csr"
        patch_generate_csr.return_value = csr

        self.harness.charm._on_certificates_relation_joined(event=event)

        relation_data = self.harness.get_relation_data(
            relation_id=peer_relation_id, app_or_unit=self.harness.charm.app.name
        )
        assert relation_data["csr"] == csr.decode()

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_creation")
    def test_given_unit_is_leader_private_key_is_stored_but_subject_config_is_not_set_when_on_certificates_relation_joined_then_request_certificate_not_made(  # noqa: E501
        self, patch_request_certificate
    ):
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "private_key": PRIVATE_KEY,
                "private_key_password": PRIVATE_KEY_PASSWORD.decode(),
            },
        )
        event = Mock()

        self.harness.charm._on_certificates_relation_joined(event=event)

        patch_request_certificate.assert_not_called()

    def test_given_unit_is_not_leader_when_on_certificate_available_then_peer_relation_data_not_updated(  # noqa: E501
        self,
    ):
        event = Mock()
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )

        self.harness.charm._on_certificate_available(event=event)

        relation_data = self.harness.get_relation_data(
            relation_id=peer_relation_id, app_or_unit=self.harness.charm.app.name
        )
        assert "certificate" not in relation_data
        assert "ca" not in relation_data
        assert "chain" not in relation_data

    def test_given_unit_is_leader_and_peer_relation_not_created_when_on_certificate_available_then_status_is_waiting(  # noqa: E501
        self,
    ):
        certificate = "whatever cert"
        ca = "whatever ca"
        chain = "whatever chain"
        event = Mock()
        event.certificate = certificate
        event.ca = ca
        event.chain = chain
        self.harness.set_leader(is_leader=True)

        self.harness.charm._on_certificate_available(event=event)

        self.assertEqual(
            WaitingStatus("Waiting for peer relation to be created"),
            self.harness.charm.unit.status,
        )

    def test_given_unit_is_leader_when_on_certificate_available_then_certificate_is_stored(self):
        certificate = "whatever cert"
        ca = "whatever ca"
        chain = "whatever chain"
        event = Mock()
        event.certificate = certificate
        event.ca = ca
        event.chain = chain
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )

        self.harness.charm._on_certificate_available(event=event)

        relation_data = self.harness.get_relation_data(
            relation_id=peer_relation_id, app_or_unit=self.harness.charm.app.name
        )
        self.assertEqual(certificate, relation_data["certificate"])
        self.assertEqual(ca, relation_data["ca"])
        self.assertEqual(chain, relation_data["chain"])

    def test_given_unit_is_leader_when_on_certificate_available_then_status_is_active(self):
        certificate = "whatever cert"
        ca = "whatever ca"
        chain = "whatever chain"
        event = Mock()
        event.certificate = certificate
        event.ca = ca
        event.chain = chain
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name="replicas", remote_app=self.harness.charm.app.name)

        self.harness.charm._on_certificate_available(event=event)

        self.assertEqual(ActiveStatus(), self.harness.charm.unit.status)

    def test_given_subject_config_not_provided_when_on_config_changed_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values={})

        self.assertEqual(
            BlockedStatus("Config `subject` must be set."), self.harness.charm.unit.status
        )

    def test_given_unit_is_leader_and_peer_relation_is_created_and_certificates_relation_not_created_when_on_config_changed_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="replicas/0")

        self.harness.update_config(key_values={"subject": "whatever subject"})

        self.assertEqual(
            BlockedStatus("Waiting for `tls-certificates` relation to be created"),
            self.harness.charm.unit.status,
        )

    @patch("charm.generate_csr")
    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_creation")
    def test_given_unit_is_leader_and_peer_relation_is_created_and_certificates_relation_is_created_when_on_config_changed_then_certificate_request_is_made(  # noqa: E501
        self, patch_certificate_request, patch_generate_csr
    ):
        csr = b"wahtever"
        patch_generate_csr.return_value = csr
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.add_relation(
            relation_name="certificates", remote_app="tls-certificates-provider"
        )
        self.harness.add_relation_unit(relation_id=peer_relation_id, remote_unit_name="replicas/0")

        self.harness.update_config(key_values={"subject": "whatever subject"})

        patch_certificate_request.assert_called_with(certificate_signing_request=csr)

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_renewal")
    def test_given_unit_is_not_leader_when_on_certificate_expiring_then_certicate_renewal_is_not_made(  # noqa: E501
        self, patch_certificate_renewal
    ):
        csr = "whatever csr"
        event = Mock()
        event.certificate_signing_request = csr
        self.harness.set_leader(is_leader=False)
        self.harness.add_relation(relation_name="replicas", remote_app=self.harness.charm.app.name)
        self.harness.update_config(key_values={"subject": "whatever"})

        self.harness.charm._on_certificate_expiring(event=event)

        patch_certificate_renewal.assert_not_called()

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_renewal")
    def test_given_unit_is_leader_but_subject_config_not_set_when_on_certificate_expiring_then_certicate_renewal_is_not_made(  # noqa: E501
        self, patch_certificate_renewal
    ):
        csr = "whatever csr"
        event = Mock()
        event.certificate_signing_request = csr
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name="replicas", remote_app=self.harness.charm.app.name)

        self.harness.charm._on_certificate_expiring(event=event)

        patch_certificate_renewal.assert_not_called()

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_renewal")
    def test_given_unit_is_leader_but_replicas_relation_not_ready_when_on_certificate_expiring_then_certicate_renewal_is_not_made(  # noqa: E501
        self, patch_certificate_renewal
    ):
        csr = "whatever csr"
        event = Mock()
        event.certificate_signing_request = csr
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(key_values={"subject": "whatever"})

        self.harness.charm._on_certificate_expiring(event=event)

        patch_certificate_renewal.assert_not_called()

    @patch("charm.generate_csr")
    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_renewal")
    def test_given_unit_is_leader_replicas_relation_ready_and_subject_config_is_set_when_on_certificate_expiring_then_certicate_renewal_is_made(  # noqa: E501
        self, patch_certificate_renewal, patch_generate_csr
    ):
        old_csr = "whatever old csr"
        new_csr = "whatever new csr"
        event = Mock()
        event.certificate_signing_request = old_csr
        patch_generate_csr.return_value = new_csr.encode()
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(key_values={"subject": "whatever"})
        relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "private_key": PRIVATE_KEY,
                "private_key_password": PRIVATE_KEY_PASSWORD.decode(),
                "csr": old_csr,
            },
        )

        self.harness.charm._on_certificate_expiring(event=event)

        patch_certificate_renewal.assert_called_with(
            old_certificate_signing_request=old_csr.encode(),
            new_certificate_signing_request=new_csr.encode(),
        )

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_renewal")
    def test_given_no_old_csr_stored_when_on_certificate_expiring_then_status_is_blocked(  # noqa: E501
        self,
        _,
    ):
        old_csr = "whatever old csr"
        event = Mock()
        event.certificate_signing_request = old_csr
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(key_values={"subject": "whatever"})
        relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "private_key": PRIVATE_KEY,
                "private_key_password": PRIVATE_KEY_PASSWORD.decode(),
            },
        )

        self.harness.charm._on_certificate_expiring(event=event)

        self.assertEqual(BlockedStatus("Old CSR not found"), self.harness.charm.unit.status)

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_renewal")
    def test_given_no_private_key_stored_when_on_certificate_expiring_then_status_is_waiting(  # noqa: E501
        self,
        _,
    ):
        old_csr = "whatever old csr"
        event = Mock()
        event.certificate_signing_request = old_csr
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(key_values={"subject": "whatever"})
        relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "csr": old_csr,
                "private_key": None,
                "private_key_password": None,
            },
        )

        self.harness.charm._on_certificate_expiring(event=event)

        self.assertEqual(
            WaitingStatus("Waiting for private key to be generated."),
            self.harness.charm.unit.status,
        )

    def test_given_peer_relation_not_created_when_on_get_certificate_action_when_then_na_is_returned(  # noqa: E501
        self,
    ):
        event = Mock()

        self.harness.charm._on_get_certificate_action(event=event)

        event.fail.assert_called_with("Certificate not available")

    def test_given_certificate_not_stored_when_on_get_certificate_action_when_then_na_is_returned(
        self,
    ):
        event = Mock()
        self.harness.add_relation(relation_name="replicas", remote_app=self.harness.charm.app.name)

        self.harness.charm._on_get_certificate_action(event=event)

        event.fail.assert_called_with("Certificate not available")

    def test_given_certificate_stored_when_on_get_certificate_action_when_then_cert_is_returned(
        self,
    ):
        certificate = "whatever certificate"
        ca = "whatever ca"
        chain = "whatever chain"
        event = Mock()
        relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "certificate": certificate,
                "ca": ca,
                "chain": chain,
            },
        )

        self.harness.charm._on_get_certificate_action(event=event)

        event.set_results.assert_called_with(
            {
                "certificate": certificate,
                "ca": ca,
                "chain": chain,
            }
        )

    def test_given_unit_is_not_leader_when_renew_certificate_action_then_event_fails(self):
        event = Mock()
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "private_key": None,
                "private_key_password": "banana",
                "csr": "whatever csr",
            },
        )

        self.harness.charm._on_renew_certificate_action(event=event)

        event.fail.assert_called_with("Unit is not leader")

    def test_given_private_key_not_stored_when_renew_certificate_action_then_event_fails(self):
        event = Mock()
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "private_key": None,
                "private_key_password": "banana",
                "csr": "whatever csr",
            },
        )

        self.harness.charm._on_renew_certificate_action(event=event)

        event.fail.assert_called_with("Private key is not stored")

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_creation")
    @patch("charm.generate_csr")
    def test_given_csr_not_stored_when_renew_certificate_action_then_certificate_creation_is_called(  # noqa: E501
        self, patch_generate_csr, patch_request_certificate_creation
    ):
        new_csr = b"whatever new csr"
        patch_generate_csr.return_value = new_csr
        event = Mock()
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "private_key": "whatever private key",
                "private_key_password": "banana",
                "csr": None,
            },
        )

        self.harness.charm._on_renew_certificate_action(event=event)

        patch_request_certificate_creation.assert_called_with(certificate_signing_request=new_csr)

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_renewal")
    @patch("charm.generate_csr")
    def test_given_private_key_and_csr_stored__when_renew_certificate_action_then_certificate_renewal_is_called(  # noqa: E501
        self, patch_generate_csr, patch_certificate_renewal
    ):
        stored_csr = "whatever stored csr"
        new_csr = "whatever new csr"
        event = Mock()
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "private_key": "whatever private key",
                "private_key_password": "banana",
                "csr": stored_csr,
            },
        )
        patch_generate_csr.return_value = new_csr.encode()

        self.harness.charm._on_renew_certificate_action(event=event)

        patch_certificate_renewal.assert_called_with(
            old_certificate_signing_request=stored_csr.encode(),
            new_certificate_signing_request=new_csr.encode(),
        )

    def test_given_no_certificates_relation_when_show_certificates_relation_data_action_then_event_fails(  # noqa: E501
        self,
    ):
        event = Mock()

        self.harness.charm._on_show_certificates_relation_data_action(event=event)

        event.fail.assert_called_with("No certificates relation")

    @patch("ops.model.Model.get_relation")
    def test_given_certificates_relation_when_show_certificates_relation_data_action_then_event_relation_data_is_returned(  # noqa: E501
        self, patch_get_relation
    ):
        event = Mock()
        relation = Mock()
        relation_data = "whatever relation data"
        relation.data = relation_data
        patch_get_relation.return_value = relation

        self.harness.charm._on_show_certificates_relation_data_action(event=event)

        event.set_results.assert_called_with({"relation-data": relation_data})

    def test_given_unit_is_not_leader_when_on_revoke_certificate_action_then_event_fails(self):
        event = Mock()
        self.harness.set_leader(is_leader=False)

        self.harness.charm._on_revoke_certificate_action(event=event)

        event.fail.assert_called_with("Unit is not leader")

    def test_given_no_replicas_relation_when_on_revoke_certificate_action_then_event_fails(self):
        event = Mock()
        self.harness.set_leader(is_leader=True)

        self.harness.charm._on_revoke_certificate_action(event=event)

        event.fail.assert_called_with("No replicas relation")

    def test_given_no_csr_in_relation_data_when_on_revoke_certificate_action_then_event_fails(
        self,
    ):
        event = Mock()
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={"csr": None},
        )

        self.harness.charm._on_revoke_certificate_action(event=event)

        event.fail.assert_called_with("No stored CSR")

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_revocation")
    def test_given_csr_in_relation_data_when_on_revoke_certificate_action_then_certificate_revocation_request_is_sent(  # noqa: E501
        self, patch_request_certificate_revocation
    ):
        event = Mock()
        csr = "whatever csr"
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "csr": csr,
                "certificate": "whatever cert",
                "ca": "whatever ca",
                "chain": "whatever chain",
            },
        )

        self.harness.charm._on_revoke_certificate_action(event=event)

        patch_request_certificate_revocation.assert_called_with(
            certificate_signing_request=csr.encode()
        )

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_revocation")
    def test_given_csr_in_relation_data_when_on_revoke_certificate_action_then_certificate_is_removed_from_peer_relation_data(  # noqa: E501
        self, _
    ):
        event = Mock()
        csr = "whatever csr"
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "csr": csr,
                "certificate": "whatever cert",
                "ca": "whatever ca",
                "chain": "whatever chain",
            },
        )

        self.harness.charm._on_revoke_certificate_action(event=event)

        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )

        assert "certificate" not in relation_data
        assert "ca" not in relation_data
        assert "chain" not in relation_data

    @patch(f"{CHARM_LIB_PATH}.TLSCertificatesRequiresV1.request_certificate_revocation")
    def test_given_no_certificate_in_relation_data_when_on_revoke_certificate_action_then_certificate_event_fails(  # noqa: E501
        self, _
    ):
        event = Mock()
        csr = "whatever csr"
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "csr": csr,
            },
        )

        self.harness.charm._on_revoke_certificate_action(event=event)

        event.fail.assert_called_with("No stored certificate")
