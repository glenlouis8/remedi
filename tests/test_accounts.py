import os
import pytest
from cryptography.fernet import Fernet


@pytest.fixture(autouse=True)
def set_encryption_key():
    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    yield
    os.environ.pop("ENCRYPTION_KEY", None)


def test_encrypt_decrypt_roundtrip():
    from remedi_platform.accounts import _fernet
    f = _fernet()
    original = "AKIAIOSFODNN7EXAMPLE"
    assert f.decrypt(f.encrypt(original.encode())).decode() == original


def test_secret_key_roundtrip():
    from remedi_platform.accounts import _fernet
    f = _fernet()
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert f.decrypt(f.encrypt(secret.encode())).decode() == secret


def test_missing_encryption_key_raises():
    if "ENCRYPTION_KEY" in os.environ:
        del os.environ["ENCRYPTION_KEY"]
    # reload so module re-reads env
    import importlib, remedi_platform.accounts as mod
    importlib.reload(mod)
    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY"):
        mod._fernet()


def test_different_keys_cannot_decrypt():
    from cryptography.fernet import Fernet, InvalidToken
    f1 = Fernet(Fernet.generate_key())
    f2 = Fernet(Fernet.generate_key())
    ciphertext = f1.encrypt(b"secret")
    with pytest.raises(InvalidToken):
        f2.decrypt(ciphertext)
