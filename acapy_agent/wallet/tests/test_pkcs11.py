from unittest import TestCase
from unittest.mock import MagicMock, patch

from acapy_agent.wallet.pkcs11 import PKCS11Signer


class TestPKCS11Signer(TestCase):
    def setUp(self):
        self.lib_path = "/path/to/lib"
        self.token_label = "test_token"
        self.pin = "1234"
        self.signer = PKCS11Signer(self.lib_path, self.token_label, self.pin)

    @patch("acapy_agent.wallet.pkcs11.pkcs11.lib")
    def test_init_session(self, mock_lib):
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_lib.return_value.get_token.return_value = mock_token
        mock_token.open.return_value = mock_session

        session = self.signer._get_session()
        
        mock_lib.assert_called_with(self.lib_path)
        mock_lib.return_value.get_token.assert_called_with(token_label=self.token_label)
        mock_token.open.assert_called_with(user_pin=self.pin, rw=True)
        self.assertEqual(session, mock_session)

    @patch("acapy_agent.wallet.pkcs11.pkcs11.lib")
    def test_init_session_with_slot_id(self, mock_lib):
        signer = PKCS11Signer(
            self.lib_path,
            self.token_label,
            self.pin,
            slot_index=2,
        )

        mock_slot = MagicMock()
        mock_slot.slot_id = 2
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_slot.get_token.return_value = mock_token
        mock_token.open.return_value = mock_session

        mock_lib.return_value.get_slots.return_value = [mock_slot]

        session = signer._get_session()

        mock_lib.return_value.get_slots.assert_called_once()
        mock_slot.get_token.assert_called_once()
        mock_token.open.assert_called_with(user_pin=self.pin, rw=True)
        self.assertEqual(session, mock_session)

    @patch("acapy_agent.wallet.pkcs11.pkcs11.lib")
    def test_init_session_with_slot_index_fallback(self, mock_lib):
        signer = PKCS11Signer(
            self.lib_path,
            self.token_label,
            self.pin,
            slot_index=1,
        )

        mock_slot_0 = MagicMock()
        mock_slot_0.slot_id = 10
        mock_slot_1 = MagicMock()
        mock_slot_1.slot_id = 20
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_slot_1.get_token.return_value = mock_token
        mock_token.open.return_value = mock_session

        mock_lib.return_value.get_slots.return_value = [mock_slot_0, mock_slot_1]

        session = signer._get_session()

        mock_lib.return_value.get_slots.assert_called_once()
        mock_slot_1.get_token.assert_called_once()
        mock_token.open.assert_called_with(user_pin=self.pin, rw=True)
        self.assertEqual(session, mock_session)

    @patch("acapy_agent.wallet.pkcs11.pkcs11.lib")
    def test_get_public_key_bytes(self, mock_lib):
        mock_session = MagicMock()
        mock_lib.return_value.get_token.return_value.open.return_value = mock_session
        
        mock_key = MagicMock()
        # Mock EC_POINT attribute access
        # DER encoded OCTET STRING (04) of length 3 (03) containing 04 AA BB
        mock_key.__getitem__.return_value = b"\x04\x03\x04\xAA\xBB" 
        mock_session.get_objects.return_value = [mock_key]

        pk_bytes = self.signer.get_public_key_bytes("label")
        
        # Should return the unwrapped bytes
        self.assertEqual(pk_bytes, b"\x04\xAA\xBB")

    @patch("acapy_agent.wallet.pkcs11.pkcs11.lib")
    def test_sign(self, mock_lib):
        mock_session = MagicMock()
        mock_lib.return_value.get_token.return_value.open.return_value = mock_session
        
        mock_key = MagicMock()
        mock_key.sign.return_value = b"signature"
        mock_session.get_objects.return_value = [mock_key]

        signature = self.signer.sign(b"message", "label")
        
        # Should hash message and call sign
        import hashlib
        digest = hashlib.sha256(b"message").digest()
        
        mock_key.sign.assert_called()
        args, kwargs = mock_key.sign.call_args
        self.assertEqual(args[0], digest)
        self.assertEqual(signature, b"signature")

    @patch("acapy_agent.wallet.pkcs11.pkcs11.lib")
    def test_create_key(self, mock_lib):
        mock_session = MagicMock()
        mock_lib.return_value.get_token.return_value.open.return_value = mock_session
        
        mock_pub = MagicMock()
        mock_priv = MagicMock()
        # Mock EC_POINT attribute access for public key
        mock_pub.__getitem__.return_value = b"\x04\x03\x04\xAA\xBB"
        mock_session.generate_keypair.return_value = (mock_pub, mock_priv)

        public_bytes = self.signer.create_key("label")
        
        # Verify call arguments
        mock_session.generate_keypair.assert_called()
        self.assertEqual(public_bytes, b"\x04\xAA\xBB")

    @patch("acapy_agent.wallet.pkcs11.pkcs11.lib")
    def test_create_iaca_certificate_write_back(self, mock_lib):
        signer = PKCS11Signer(
            self.lib_path,
            self.token_label,
            self.pin,
            iaca_write_back=True,
        )

        mock_session = MagicMock()
        mock_token = MagicMock()
        mock_token.open.return_value = mock_session
        mock_lib.return_value.get_token.return_value = mock_token

        mock_lib.return_value.create_iaca_certificate.return_value = (
            "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----"
        )

        cert = signer.create_iaca_certificate(
            label="x509-signer",
            kid="kid-1",
            public_key=b"public",
        )

        self.assertIn("BEGIN CERTIFICATE", cert)
        mock_session.create_object.assert_called_once()

    @patch("acapy_agent.wallet.pkcs11.pkcs11.lib")
    def test_create_iaca_certificate_standard_fallback(self, mock_lib):
        signer = PKCS11Signer(
            self.lib_path,
            self.token_label,
            self.pin,
            iaca_write_back=False,
        )

        mock_session = MagicMock()
        mock_token = MagicMock()
        mock_token.open.return_value = mock_session
        mock_lib.return_value.get_token.return_value = mock_token

        with patch.object(
            signer,
            "_create_standard_iaca_certificate",
            return_value="-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----",
        ) as mock_standard:
            cert = signer.create_iaca_certificate(
                label="x509-signer",
                kid="kid-1",
                public_key=b"public",
            )

        self.assertIn("BEGIN CERTIFICATE", cert)
        mock_standard.assert_called_once()
