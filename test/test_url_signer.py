import base64
import hashlib
import hmac
from unittest import TestCase
from datetime import datetime, timedelta

from six import text_type

from thumbor_expire.base64_hmac_sha1_expire import UrlSigner


class Base64HmacSha1UrlSignerTestCase(TestCase):
    def test_can_create_signer(self):
        signer = UrlSigner(security_key="something")
        self.assertTrue(isinstance(signer, UrlSigner))
        self.assertEqual(signer.security_key, "something")

    def test_can_sign_url(self):
        security_key = "something"
        signer = UrlSigner(security_key=security_key)

        expire_time = datetime.utcnow() + timedelta(seconds=10)
        url = "/10x11:12x13/-300x-300/center/middle/smart/some/image.jpg"
        expire_str = expire_time.strftime('%Y%m%d%H%M%S')

        expected = base64.urlsafe_b64encode(
            hmac.new(
                security_key.encode(), text_type(expire_str + url).encode("utf-8"), hashlib.sha1
            ).digest()
        )
        actual = signer.signature(expire_str, url)
        self.assertEqual(actual, expected)

    def test_can_unsign_url(self):
        security_key = "something"
        signer = UrlSigner(security_key=security_key)

        url = "/10x11:12x13/-300x-300/center/middle/smart/some/image.jpg"
        expire_str = ''

        expected = base64.urlsafe_b64encode(
            hmac.new(
                security_key.encode(), text_type(expire_str + url).encode("utf-8"), hashlib.sha1
            ).digest()
        )
        actual = signer.signature(expire_str, url)
        self.assertEqual(actual, expected)
