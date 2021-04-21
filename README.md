# thumbor-expire
Add timeout verification for thumbor

## Use 

* Server side

thumbor config file set `URL_SIGNER = thumbor_expire.base64_hmac_sha1_expire`


* Client side

use `from thumbor_expire.crypto import CryptoURL` class and pass expire argument, accept type `:obj:`int` | :obj:`float` | :obj:`datetime.timedelta` | \
        :obj:`datetime.datetime` | :obj:`datetime.time`, optional`
