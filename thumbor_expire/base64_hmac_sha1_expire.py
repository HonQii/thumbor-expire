# -*- coding: utf-8 -*-
from datetime import datetime
import base64
import hashlib
import hmac
from six import text_type
from libthumbor.url_signers import BaseUrlSigner


class UrlSigner(BaseUrlSigner):
    """
    Expects a signature of the form <hmac>:<expiry>, where
       - hmac is a urlsafe base64 encoded HMAC using SHA1.
       - expiry encodes the time in UTC until the url is valid, in the format YYYYMMDDHHMMSS.
       - eg: -8yJNS5QbnIHRqCOTGsqgLnCKk8=:20210326142432
    """

    def validate(self, actual_signature, url):
        if ':' in actual_signature:
            sha1_str, expire_time = actual_signature.split(':')
            if not self._valid_expire_time(expire_time):
                return False

            url_signature = self.signature(expire_time, url)
            return url_signature == sha1_str
        else:
            url_signature = self.signature('', url)
            return url_signature == actual_signature

    def _valid_expire_time(self, expire_time):
        try:
            expiry = datetime.strptime(expire_time, '%Y%m%d%H%M%S')
            return datetime.utcnow() < expiry
        except ValueError:
            return False

    def signature(self, expire_time, url):
        security_key = text_type(self.security_key).encode('utf-8')
        full_url = text_type(expire_time + '/' + url).encode('utf-8')
        return base64.urlsafe_b64encode(hmac.new(security_key, full_url, hashlib.sha1).digest())
