import datetime
from unittest import TestCase
import base64, hmac, hashlib
from six import text_type
from libthumbor.url import plain_image_url
from thumbor_expire.crypto import CryptoURL

IMAGE_URL = "my.server.com/some/path/to/image.jpg"
KEY = "my-security-key"


def _crypto_str(expire, url):
    expire_str = expire.strftime('%Y%m%d%H%M%S')
    return "/%s:%s" % (base64.urlsafe_b64encode(
        hmac.new(
            KEY.encode(), text_type(expire_str + '/' + url).encode("utf-8"), hashlib.sha1
        ).digest()), expire_str
    )


class GenerateTestCase(TestCase):
    def setUp(self):
        self.crypto = CryptoURL(KEY)

    def test_should_pass_expire_to_generate_and_get_an_expire_url(self):
        expire_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=1000)
        url = self.crypto.generate(
            image_url=IMAGE_URL, crop=((10, 20), (30, 40)), expire=expire_time
        )
        self.assertTrue(url.startswith(_crypto_str(expire_time,
                                                   plain_image_url(image_url=IMAGE_URL,
                                                                   crop=((10, 20), (30, 40))))))

    def test_should_not_get_an_expire_url_when_expire_is_null(self):
        url = self.crypto.generate(
            image_url=IMAGE_URL, crop=((10, 20), (30, 40))
        )
        security = url.split('/')[1]
        self.assertFalse(':' in security)
