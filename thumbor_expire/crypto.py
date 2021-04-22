from datetime import datetime, timedelta, time, date
import base64
from six import text_type, PY3

from libthumbor.crypto import CryptoURL as ThumborCryptoURL
from libthumbor.url import plain_image_url


class CryptoURL(ThumborCryptoURL):

    def generate_url(self, url, expire = None):
        expire_url = url
        if expire:
            if isinstance(expire, (int, float)):
                expire = datetime.utcnow() + timedelta(seconds=expire)
            elif isinstance(expire, datetime):
                expire = expire
            elif isinstance(expire, date):
                expire = datetime.combine(expire, time.min)
            elif isinstance(expire, time):
                expire = datetime.utcnow() + (datetime.combine(date.min, expire) - datetime.min)
            elif isinstance(expire, timedelta):
                expire = datetime.utcnow() + expire

            expire_str = expire.strftime('%Y%m%d%H%M%S')
            expire_url = '%s/%s' % (expire_str, expire_url)

        _hmac = self.hmac.copy()
        _hmac.update(text_type(expire_url).encode('utf-8'))
        signature = base64.urlsafe_b64encode(_hmac.digest())

        if PY3:
            signature = signature.decode('ascii')

        if expire:
            return '/%s:%s/%s' % (signature, expire_str, url)
        else:
            return '/%s/%s' % (signature, url)

    def generate_new(self, options):
        url = plain_image_url(**options)
        return self.generate_url(url, options.get('expire', None))

    def generate_options(self,
                         image_url,
                         width=0,
                         height=0,
                         smart=False,
                         meta=False,
                         trim=None,
                         adaptive=False,
                         full=False,
                         fit_in=False,
                         horizontal_flip=False,
                         vertical_flip=False,
                         halign='center',
                         valign='middle',
                         expire=None,  #
                         crop_left=None,
                         crop_top=None,
                         crop_right=None,
                         crop_bottom=None,
                         filters=None):
        """
        :param expire: :obj:`int` | :obj:`float` | :obj:`datetime.timedelta` | \
        :obj:`datetime.datetime` | :obj:`datetime.time`, optional
        """
        return self.generate(**{k: v for k, v in locals().items() if v is not None})


