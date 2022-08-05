# Copyright 2021 Guillaume Belanger
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from ops import testing
from ops.model import BlockedStatus, MaintenanceStatus, WaitingStatus

from charm import TLSRequirerOperatorCharm

testing.SIMULATE_CAN_CONNECT = True

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

    def test_given_unit_is_not_leader_when_on_install_then_status_is_maintenance(self):
        event = Mock()
        self.harness.set_leader(is_leader=False)

        self.harness.charm._on_install(event=event)

        self.assertEqual(
            MaintenanceStatus(),
            self.harness.charm.unit.status,
        )

    def test_given_replicas_relation_not_yet_created_when_on_install_then_status_is_waiting(self):
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(key_values={"subject": "whatever"})

        self.harness.charm._on_install(event=event)

        self.assertEqual(
            WaitingStatus("Waiting for peer relation to be created"),
            self.harness.charm.unit.status,
        )

    def test_given_config_subject_not_set_when_on_install_then_status_is_blocked(self):
        event = Mock()
        self.harness.set_leader(is_leader=True)

        self.harness.charm._on_install(event=event)

        self.assertEqual(
            BlockedStatus("Config `subject` must be set."),
            self.harness.charm.unit.status,
        )

    def test_given_replicas_relation_created_and_config_subject_set_when_on_install_then_private_key_is_generated(  # noqa: E501
        self,
    ):
        event = Mock()
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation("replicas", self.harness.charm.app.name)
        self.harness.update_config(key_values={"subject": "whatever"})

        self.harness.charm._on_install(event=event)

        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app.name
        )

        serialization.load_pem_private_key(
            data=relation_data["private_key"].encode(),
            password=relation_data["private_key_password"].encode(),
        )

    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v1.tls_certificates.TLSCertificatesRequiresV1.request_certificate_creation"  # noqa: E501, W505
    )
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
    @patch(
        "charms.tls_certificates_interface.v1.tls_certificates.TLSCertificatesRequiresV1.request_certificate_creation"  # noqa: E501, W505
    )
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
    @patch(
        "charms.tls_certificates_interface.v1.tls_certificates.TLSCertificatesRequiresV1.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_unit_is_leader_and_peer_relation_is_set_but_private_key_not_stored_when_on_certificates_relation_joined_then_certificate_request_is_not_made(  # noqa: E501
        self, patch_request_certificate, patch_generate_csr
    ):
        self.harness.update_config(key_values={"subject": "whatever"})
        self.harness.set_leader(is_leader=True)
        event = Mock()
        patch_generate_csr.return_value = b"whatever csr"
        key_values = {
            "private_key_password": PRIVATE_KEY_PASSWORD.decode(),
        }
        peer_relation_id = self.harness.add_relation(
            relation_name="replicas", remote_app=self.harness.charm.app.name
        )
        self.harness.update_relation_data(
            relation_id=peer_relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values=key_values,
        )

        self.harness.charm._on_certificates_relation_joined(event=event)

        patch_request_certificate.assert_not_called()

    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v1.tls_certificates.TLSCertificatesRequiresV1.request_certificate_creation"  # noqa: E501, W505
    )
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
    @patch(
        "charms.tls_certificates_interface.v1.tls_certificates.TLSCertificatesRequiresV1.request_certificate_creation"  # noqa: E501, W505
    )
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
