# encoding: utf-8
import base64
import hashlib
import hmac
import re
import six
from six.moves.urllib.parse import quote

from Crypto.Cipher import AES


class Url(object):

    unsafe_or_hash = r'(?:(?:(?P<unsafe>unsafe)|(?P<hash>[^/]{28,}?))/)?'
    debug = '(?:(?P<debug>debug)/)?'
    meta = '(?:(?P<meta>meta)/)?'
    trim = '(?:(?P<trim>trim(?::(?:top-left|bottom-right))?(?::\d+)?)/)?'
    crop = '(?:(?P<crop_left>\d+)x(?P<crop_top>\d+):(?P<crop_right>\d+)x(?P<crop_bottom>\d+)/)?'
    fit_in = '(?:(?P<adaptive>adaptive-)?(?P<full>full-)?(?P<fit_in>fit-in)/)?'
    dimensions = '(?:(?P<horizontal_flip>-)?(?P<width>(?:\d+|orig))?x(?P<vertical_flip>-)?(?P<height>(?:\d+|orig))?/)?'
    halign = r'(?:(?P<halign>left|right|center)/)?'
    valign = r'(?:(?P<valign>top|bottom|middle)/)?'
    smart = r'(?:(?P<smart>smart)/)?'
    filters = r'(?:filters:(?P<filters>.+?\))/)?'
    image = r'(?P<image>.+)'

    compiled_regex = None

    @classmethod
    def regex(cls, has_unsafe_or_hash=True):
        reg = ['/?']

        if has_unsafe_or_hash:
            reg.append(cls.unsafe_or_hash)
        reg.append(cls.debug)
        reg.append(cls.meta)
        reg.append(cls.trim)
        reg.append(cls.crop)
        reg.append(cls.fit_in)
        reg.append(cls.dimensions)
        reg.append(cls.halign)
        reg.append(cls.valign)
        reg.append(cls.smart)
        reg.append(cls.filters)
        reg.append(cls.image)

        return ''.join(reg)

    @classmethod
    def parse_decrypted(cls, url):
        if cls.compiled_regex:
            reg = cls.compiled_regex
        else:
            reg = cls.compiled_regex = re.compile(cls.regex(has_unsafe_or_hash=False))

        result = reg.match(url)

        if not result:
            return None

        result = result.groupdict()

        int_or_0 = lambda value: 0 if value is None else int(value)
        values = {
            'debug': result['debug'] == 'debug',
            'meta': result['meta'] == 'meta',
            'trim': result['trim'],
            'crop': {
                'left': int_or_0(result['crop_left']),
                'top': int_or_0(result['crop_top']),
                'right': int_or_0(result['crop_right']),
                'bottom': int_or_0(result['crop_bottom'])
            },
            'adaptive': result['adaptive'] == 'adaptive',
            'full': result['full'] == 'full',
            'fit_in': result['fit_in'] == 'fit-in',
            'width': result['width'] == 'orig' and 'orig' or int_or_0(result['width']),
            'height': result['height'] == 'orig' and 'orig' or int_or_0(result['height']),
            'horizontal_flip': result['horizontal_flip'] == '-',
            'vertical_flip': result['vertical_flip'] == '-',
            'halign': result['halign'] or 'center',
            'valign': result['valign'] or 'middle',
            'smart': result['smart'] == 'smart',
            'filters': result['filters'] or '',
            'image': 'image' in result and result['image'] or None
        }

        return values

    @classmethod
    def generate_options(cls,
                         debug=False,
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
                         crop_left=None,
                         crop_top=None,
                         crop_right=None,
                         crop_bottom=None,
                         filters=None):

        url = []

        if debug:
            url.append('debug')

        if meta:
            url.append('meta')

        if trim:
            if isinstance(trim, bool):
                url.append('trim')
            else:
                url.append('trim:%s' % trim)

        crop = crop_left or crop_top or crop_right or crop_bottom
        if crop:
            url.append('%sx%s:%sx%s' % (
                crop_left,
                crop_top,
                crop_right,
                crop_bottom
            ))

        if fit_in:
            fit_ops = []
            if adaptive:
                fit_ops.append('adaptive')
            if full:
                fit_ops.append('full')
            fit_ops.append('fit-in')
            url.append('-'.join(fit_ops))

        if horizontal_flip:
            width = '-%s' % width
        if vertical_flip:
            height = '-%s' % height

        if width or height:
            url.append('%sx%s' % (width, height))

        if halign != 'center':
            url.append(halign)
        if valign != 'middle':
            url.append(valign)

        if smart:
            url.append('smart')

        if filters:
            url.append('filters:%s' % filters)

        return '/'.join(url)

    @classmethod
    def encode_url(kls, url):
        return quote(url, '/:?%=&()~",\'')


class Cryptor(object):
    def __init__(self, security_key):
        if isinstance(security_key, six.string_types):
            security_key = security_key.encode('utf-8')
        self.security_key = (security_key * 16)[:16]

    def encrypt(self,
                width,
                height,
                smart,
                adaptive,
                full,
                fit_in,
                flip_horizontal,
                flip_vertical,
                halign,
                valign,
                trim,
                crop_left,
                crop_top,
                crop_right,
                crop_bottom,
                filters,
                image):

        generated_url = Url.generate_options(
            width=width,
            height=height,
            smart=smart,
            meta=False,
            adaptive=adaptive,
            full=full,
            fit_in=fit_in,
            horizontal_flip=flip_horizontal,
            vertical_flip=flip_vertical,
            halign=halign,
            valign=valign,
            trim=trim,
            crop_left=crop_left,
            crop_top=crop_top,
            crop_right=crop_right,
            crop_bottom=crop_bottom,
            filters=filters
        )

        url = "%s/%s" % (generated_url, hashlib.md5(image.encode('utf-8')).hexdigest())

        pad = lambda b: b + (16 - len(b) % 16) * b"{"
        cipher = AES.new(self.security_key)
        encrypted = base64.urlsafe_b64encode(cipher.encrypt(pad(url.encode('utf-8'))))

        return encrypted.decode('utf-8')

    def get_options(self, encrypted_url_part, image_url):
        try:
            opt = self.decrypt(encrypted_url_part)
        except ValueError:
            opt = None

        if not opt and not self.security_key and self.context.config.STORES_CRYPTO_KEY_FOR_EACH_IMAGE:
            security_key = self.storage.get_crypto(image_url)

            if security_key is not None:
                cr = Cryptor(security_key)
                try:
                    opt = cr.decrypt(encrypted_url_part)
                except ValueError:
                    opt = None

        if opt is None:
            return None

        image_hash = opt and opt.get('image_hash')
        image_hash = image_hash[1:] if image_hash and image_hash.startswith('/') else image_hash

        path_hash = hashlib.md5(image_url.encode('utf-8')).hexdigest()

        if not image_hash or image_hash != path_hash:
            return None

        opt['image'] = image_url
        opt['hash'] = opt['image_hash']
        del opt['image_hash']

        return opt

    def decrypt(self, encrypted):
        cipher = AES.new(self.security_key)

        # try:
        debased = base64.urlsafe_b64decode(encrypted.encode('utf-8'))
        decrypted = cipher.decrypt(debased).rstrip(b'{').decode('utf-8')
        # except TypeError:
        #     return None

        result = Url.parse_decrypted('/%s' % decrypted)

        result['image_hash'] = result['image']
        del result['image']

        return result


class Signer:
    def __init__(self, security_key):
        if isinstance(security_key, six.string_types):
            security_key = security_key.encode('utf-8')
        self.security_key = security_key

    def validate(self, actual_signature, url):
        url_signature = self.signature(url)
        return url_signature == actual_signature

    def signature(self, url):
        result = base64.urlsafe_b64encode(
            hmac.new(self.security_key, url.encode('utf-8'), hashlib.sha1).digest())
        # hmac.new(self.security_key, unicode(url).encode('utf-8'), hashlib.sha1).digest())
        return result.decode()
