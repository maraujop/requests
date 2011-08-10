# -*- coding: utf-8 -*-

"""
requests.models
~~~~~~~~~~~~~~~

"""

import urllib
import urllib2
import socket
import zlib

from urllib2 import HTTPError
from urlparse import urlparse, urlunparse, parse_qs
from datetime import datetime

from .config import settings
from .monkeys import Request as _Request, HTTPBasicAuthHandler, HTTPForcedBasicAuthHandler, HTTPDigestAuthHandler, HTTPRedirectHandler
from .structures import CaseInsensitiveDict
from .packages.poster.encode import multipart_encode
from .packages.poster.streaminghttp import register_openers, get_handlers
from .exceptions import RequestException, AuthenticationError, Timeout, URLRequired, InvalidMethod


REDIRECT_STATI = (301, 302, 303, 307)
OAUTH_VERSION = '1.0' 

class Request(object):
    """The :class:`Request <models.Request>` object. It carries out all functionality of
    Requests. Recommended interface is with the Requests functions.
    """

    _METHODS = ('GET', 'HEAD', 'PUT', 'POST', 'DELETE', 'PATCH')

    def __init__(self,
        url=None, headers=dict(), files=None, method=None, data=dict(),
        params=dict(), auth=None, cookiejar=None, timeout=None, redirect=False,
        allow_redirects=False, proxies=None):

        socket.setdefaulttimeout(timeout)

        #: Request URL.
        self.url = url
        #: Oauth hack
        self.normalized_url = url
        #: Dictonary of HTTP Headers to attach to the :class:`Request <models.Request>`.
        self.headers = headers
        #: Dictionary of files to multipart upload (``{filename: content}``).
        self.files = files
        #: HTTP Method to use. Available: GET, HEAD, PUT, POST, DELETE.
        self.method = method
        #: Dictionary or byte of request body data to attach to the
        #: :class:`Request <models.Request>`.
        self.data = None
        #: Dictionary or byte of querystring data to attach to the
        #: :class:`Request <models.Request>`.
        self.params = None
        #: True if :class:`Request <models.Request>` is part of a redirect chain (disables history
        #: and HTTPError storage).
        self.redirect = redirect
        #: Set to True if full redirects are allowed (e.g. re-POST-ing of data at new ``Location``)
        self.allow_redirects = allow_redirects
        # Dictionary mapping protocol to the URL of the proxy (e.g. {'http': 'foo.bar:3128'})
        self.proxies = proxies

        self.data, self._enc_data = self._encode_params(data)
        self.params, self._enc_params = self._encode_params(params)

        #: :class:`Response <models.Response>` instance, containing
        #: content and metadata of HTTP Response, once :attr:`sent <send>`.
        self.response = Response()

        if isinstance(auth, (list, tuple)):
            try:
                #: Oauth, Consumer & Token (Optional)
                from oauth2 import Consumer, Token
                if len(auth) == 2 and isinstance(auth[0], Consumer) and isinstance(auth[1], Token):
                    self.consumer = auth[0]
                    self.token = auth[1]
                    auth = 'oauth'

                    from oauth2 import SignatureMethod_HMAC_SHA1
                    self.signature = SignatureMethod_HMAC_SHA1()

                    if self.params is None: 
                        self.params = dict()

                    import time
                    import random

                    self.params['oauth_consumer_key'] = self.consumer.key
                    self.params['oauth_timestamp'] = str(int(time.time())) #cls.make_timestamp()
                    self.params['oauth_nonce'] = str(random.randint(0, 100000000)) #cls.make_nonce()
                    self.params['oauth_version'] = OAUTH_VERSION

                    self.params['oauth_token'] = self.token.key
                    if self.token.verifier:
                        self.params['oauth_verifier'] = self.token.verifier

                else:
                    auth = AuthObject(*auth)
            except IndexError:
                auth = AuthObject(*auth)
        if not auth:
            auth = auth_manager.get_auth(self.url)

        #: :class:`AuthObject` to attach to :class:`Request <models.Request>`.
        self.auth = auth
        #: CookieJar to attach to :class:`Request <models.Request>`.
        self.cookiejar = cookiejar
        #: True if Request has been sent.
        self.sent = False


        # Header manipulation and defaults.

        if settings.accept_gzip:
            settings.base_headers.update({'Accept-Encoding': 'gzip'})

        if headers:
            headers = CaseInsensitiveDict(self.headers)
        else:
            headers = CaseInsensitiveDict()

        for (k, v) in settings.base_headers.items():
            if k not in headers:
                headers[k] = v

        self.headers = headers


    def __repr__(self):
        return '<Request [%s]>' % (self.method)


    def __setattr__(self, name, value):
        if (name == 'method') and (value):
            if not value in self._METHODS:
                raise InvalidMethod()

        object.__setattr__(self, name, value)


    def _checks(self):
        """Deterministic checks for consistency."""

        if not self.url:
            raise URLRequired


    def _get_opener(self):
        """Creates appropriate opener object for urllib2."""

        _handlers = []

        if self.cookiejar is not None:
            _handlers.append(urllib2.HTTPCookieProcessor(self.cookiejar))

        if self.auth:
            if not isinstance(self.auth.handler, (urllib2.AbstractBasicAuthHandler, urllib2.AbstractDigestAuthHandler)):
                auth_manager.add_password(self.auth.realm, self.url, self.auth.username, self.auth.password)
                self.auth.handler = self.auth.handler(auth_manager)
                auth_manager.add_auth(self.url, self.auth)

            _handlers.append(self.auth.handler)

        if self.proxies:
            _handlers.append(urllib2.ProxyHandler(self.proxies))

        _handlers.append(HTTPRedirectHandler)

        if not _handlers:
            return urllib2.urlopen

        if self.data or self.files:
            _handlers.extend(get_handlers())

        opener = urllib2.build_opener(*_handlers)

        if self.headers:
            # Allow default headers in the opener to be overloaded
            normal_keys = [k.capitalize() for k in self.headers]
            for key, val in opener.addheaders[:]:
                if key not in normal_keys:
                    continue
                # Remove it, we have a value to take its place
                opener.addheaders.remove((key, val))

        return opener.open


    def _build_response(self, resp):
        """Build internal :class:`Response <models.Response>` object from given response."""

        def build(resp):

            response = Response()
            response.status_code = getattr(resp, 'code', None)

            try:
                response.headers = CaseInsensitiveDict(getattr(resp.info(), 'dict', None))
                response.read = resp.read
                response.close = resp.close
            except AttributeError:
                pass

            response.url = getattr(resp, 'url', None)

            return response


        history = []

        r = build(resp)

        if r.status_code in REDIRECT_STATI and not self.redirect:

            while (
                ('location' in r.headers) and
                ((self.method in ('GET', 'HEAD')) or
                (r.status_code is 303) or
                (self.allow_redirects))
            ):

                history.append(r)

                url = r.headers['location']

                # Facilitate non-RFC2616-compliant 'location' headers
                # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
                if not urlparse(url).netloc:
                    parent_url_components = urlparse(self.url)
                    url = '%s://%s/%s' % (parent_url_components.scheme, parent_url_components.netloc, url)

                # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
                if r.status_code is 303:
                    method = 'GET'
                else:
                    method = self.method

                request = Request(
                    url, self.headers, self.files, method,
                    self.data, self.params, self.auth, self.cookiejar,
                    redirect=True
                )
                request.send()
                r = request.response

            r.history = history

        self.response = r


    @staticmethod
    def _encode_params(data):
        """Encode parameters in a piece of data.

        If the data supplied is a dictionary, encodes each parameter in it, and
        returns a list of tuples containing the encoded parameters, and a urlencoded
        version of that.

        Otherwise, assumes the data is already encoded appropriately, and
        returns it twice.

        """
        if hasattr(data, 'items'):
            result = []
            for k, vs in data.items():
                for v in isinstance(vs, list) and vs or [vs]:
                    result.append((k.encode('utf-8') if isinstance(k, unicode) else k,
                                   v.encode('utf-8') if isinstance(v, unicode) else v))
            return result, urllib.urlencode(result, doseq=True)
        else:
            return data, data


    def _build_url(self):
        """Build the actual URL to use"""

        # Support for unicode domain names.
        parsed_url = list(urlparse(self.url))
        parsed_url[1] = parsed_url[1].encode('idna')
        self.url = urlunparse(parsed_url)

        if self._enc_params:
            if urlparse(self.url).query:
                return '%s&%s' % (self.url, self._enc_params)
            else:
                return '%s?%s' % (self.url, self._enc_params)
        else:
            return self.url

    def _to_url(self):
        """Serialize as a URL for a GET request."""
        base_url = urlparse(self.url)
        try:
            query = base_url.query
        except AttributeError:
            # must be python <2.5
            query = base_url[4]
        query = parse_qs(query)
        for k, v in self.params.items():
            query.setdefault(k, []).append(v)
        
        try:
            scheme = base_url.scheme
            netloc = base_url.netloc
            path = base_url.path
            params = base_url.params
            fragment = base_url.fragment
        except AttributeError:
            # must be python <2.5
            scheme = base_url[0]
            netloc = base_url[1]
            path = base_url[2]
            params = base_url[3]
            fragment = base_url[5]
        
        url = (scheme, netloc, path, params,
               urllib.urlencode(query, True), fragment)
        return urlunparse(url)

    @staticmethod
    def _split_url_string(param_str):
        """Turn URL string into parameters."""
        parameters = parse_qs(param_str.encode('utf-8'), keep_blank_values=True)
        for k, v in parameters.iteritems():
            parameters[k] = urllib.unquote(v[0])
        return parameters

    def get_normalized_parameters(self):
        """Return a string that contains the parameters that must be signed. 
        This method is called by oauth2 SignatureMethod subclass self.signature
        Thus it need to be called this way or we need to create our own SignatureMethod"""
        from oauth2 import to_utf8_if_string, to_utf8

        items = []
        for key, value in self.params.iteritems():
            if key == 'oauth_signature':
                continue
            # 1.0a/9.1.1 states that kvp must be sorted by key, then by value,
            # so we unpack sequence values into multiple items for sorting.
            if isinstance(value, basestring):
                items.append((to_utf8_if_string(key), to_utf8(value)))
            else:
                try:
                    value = list(value)
                except TypeError, e:
                    assert 'is not iterable' in str(e)
                    items.append((to_utf8_if_string(key), to_utf8_if_string(value)))
                else:
                    items.extend((to_utf8_if_string(key), to_utf8_if_string(item)) for item in value)

        # Include any query string parameters from the provided URL
        query = urlparse(self.url)[4]

        url_items = self._split_url_string(query).items()
        url_items = [(to_utf8(k), to_utf8(v)) for k, v in url_items if k != 'oauth_signature' ]
        items.extend(url_items)

        items.sort()
        encoded_str = urllib.urlencode(items)
        # Encode signature parameters per Oauth Core 1.0 protocol
        # spec draft 7, section 3.6
        # (http://tools.ietf.org/html/draft-hammer-oauth-07#section-3.6)
        # Spaces must be encoded with "%20" instead of "+"
        return encoded_str.replace('+', '%20').replace('%7E', '~')

    def _sign_request(self):
        """Using self.signature, self.consumer and self.token, sign request
        for Oauth authentication handling. This means adding `oatuh_signature_method`
        and `oauth_signature` to request parameters."""

        #if not self.is_form_encoded:
            # according to
            # http://oauth.googlecode.com/svn/spec/ext/body_hash/1.0/oauth-bodyhash.html
            # section 4.1.1 "OAuth Consumers MUST NOT include an
            # oauth_body_hash parameter on requests with form-encoded
            # request bodies."
            # self['oauth_body_hash'] = base64.b64encode(sha(self.body).digest())

        self.params['oauth_signature_method'] = self.signature.name
        self.params['oauth_signature'] = self.signature.sign(self, self.consumer, self.token)
 

    def send(self, anyway=False):
        """Sends the request. Returns True of successful, false if not.
        If there was an HTTPError during transmission,
        self.response.status_code will contain the HTTPError code.

        Once a request is successfully sent, `sent` will equal True.

        :param anyway: If True, request will be sent, even if it has
        already been sent.
        """
        self._checks()
        success = False

        # Logging
        if settings.verbose:
            settings.verbose.write('%s   %s   %s\n' % (
                datetime.now().isoformat(), self.method, self.url
            ))

        # If authentication is set to oauth, we need to sign the request
        # Generate the oauth url
        if self.auth == "oauth":
            self._sign_request()
            self.url = self._to_url()
            # Very hacky, adapting _get_opener is the right way to do this
            self.auth = None

        url = self._build_url()
        if self.method in ('GET', 'HEAD', 'DELETE'):
            req = _Request(url, method=self.method)
        else:

            if self.files:
                register_openers()

                if self.data:
                    self.files.update(self.data)

                datagen, headers = multipart_encode(self.files)
                req = _Request(url, data=datagen, headers=headers, method=self.method)

            else:
                req = _Request(url, data=self._enc_data, method=self.method)

        if self.headers:
            req.headers.update(self.headers)

        if not self.sent or anyway:

            try:
                opener = self._get_opener()
                resp = opener(req)

                if self.cookiejar is not None:
                    self.cookiejar.extract_cookies(resp, req)

            except (urllib2.HTTPError, urllib2.URLError), why:
                if hasattr(why, 'reason'):
                    if isinstance(why.reason, socket.timeout):
                        why = Timeout(why)

                self._build_response(why)
                if not self.redirect:
                    self.response.error = why

            else:
                self._build_response(resp)
                self.response.ok = True

            self.response.cached = False
        else:
            self.response.cached = True

        self.sent = self.response.ok


        return self.sent



class Response(object):
    """The core :class:`Response <models.Response>` object. All
    :class:`Request <models.Request>` objects contain a
    :class:`response <models.Response>` attribute, which is an instance
    of this class.
    """

    def __init__(self):
        #: Raw content of the response, in bytes.
        #: If ``content-encoding`` of response was set to ``gzip``, the
        #: response data will be automatically deflated.
        self._content = None
        #: Integer Code of responded HTTP Status.
        self.status_code = None
        #: Case-insensitive Dictionary of Response Headers.
        #: For example, ``headers['content-encoding']`` will return the
        #: value of a ``'Content-Encoding'`` response header.
        self.headers = CaseInsensitiveDict()
        #: Final URL location of Response.
        self.url = None
        #: True if no :attr:`error` occured.
        self.ok = False
        #: Resulting :class:`HTTPError` of request, if one occured.
        self.error = None
        #: True, if the response :attr:`content` is cached locally.
        self.cached = False
        #: A list of :class:`Response <models.Response>` objects from
        #: the history of the Request. Any redirect responses will end
        #: up here.
        self.history = []


    def __repr__(self):
        return '<Response [%s]>' % (self.status_code)


    def __nonzero__(self):
        """Returns true if :attr:`status_code` is 'OK'."""
        return not self.error


    def __getattr__(self, name):
        """Read and returns the full stream when accessing to :attr: `content`"""
        if name == 'content':
            if self._content is not None:
                return self._content
            self._content = self.read()
            if self.headers.get('content-encoding', '') == 'gzip':
                try:
                    self._content = zlib.decompress(self._content, 16+zlib.MAX_WBITS)
                except zlib.error:
                    pass
            return self._content


    def raise_for_status(self):
        """Raises stored :class:`HTTPError` or :class:`URLError`, if one occured."""
        if self.error:
            raise self.error


class AuthManager(object):
    """Requests Authentication Manager."""

    def __new__(cls):
        singleton = cls.__dict__.get('__singleton__')
        if singleton is not None:
            return singleton

        cls.__singleton__ = singleton = object.__new__(cls)

        return singleton


    def __init__(self):
        self.passwd = {}
        self._auth = {}


    def __repr__(self):
        return '<AuthManager [%s]>' % (self.method)


    def add_auth(self, uri, auth):
        """Registers AuthObject to AuthManager."""

        uri = self.reduce_uri(uri, False)

        # try to make it an AuthObject
        if not isinstance(auth, AuthObject):
            try:
                auth = AuthObject(*auth)
            except TypeError:
                pass

        self._auth[uri] = auth


    def add_password(self, realm, uri, user, passwd):
        """Adds password to AuthManager."""
        # uri could be a single URI or a sequence
        if isinstance(uri, basestring):
            uri = [uri]

        reduced_uri = tuple([self.reduce_uri(u, False) for u in uri])

        if reduced_uri not in self.passwd:
            self.passwd[reduced_uri] = {}
        self.passwd[reduced_uri] = (user, passwd)


    def find_user_password(self, realm, authuri):
        for uris, authinfo in self.passwd.iteritems():
            reduced_authuri = self.reduce_uri(authuri, False)
            for uri in uris:
                if self.is_suburi(uri, reduced_authuri):
                    return authinfo

        return (None, None)


    def get_auth(self, uri):
        (in_domain, in_path) = self.reduce_uri(uri, False)

        for domain, path, authority in (
            (i[0][0], i[0][1], i[1]) for i in self._auth.iteritems()
        ):
            if in_domain == domain:
                if path in in_path:
                    return authority


    def reduce_uri(self, uri, default_port=True):
        """Accept authority or URI and extract only the authority and path."""
        # note HTTP URLs do not have a userinfo component
        parts = urllib2.urlparse.urlsplit(uri)
        if parts[1]:
            # URI
            scheme = parts[0]
            authority = parts[1]
            path = parts[2] or '/'
        else:
            # host or host:port
            scheme = None
            authority = uri
            path = '/'
        host, port = urllib2.splitport(authority)
        if default_port and port is None and scheme is not None:
            dport = {"http": 80,
                     "https": 443,
                     }.get(scheme)
            if dport is not None:
                authority = "%s:%d" % (host, dport)

        return authority, path


    def is_suburi(self, base, test):
        """Check if test is below base in a URI tree

        Both args must be URIs in reduced form.
        """
        if base == test:
            return True
        if base[0] != test[0]:
            return False
        common = urllib2.posixpath.commonprefix((base[1], test[1]))
        if len(common) == len(base[1]):
            return True
        return False


    def empty(self):
        self.passwd = {}


    def remove(self, uri, realm=None):
        # uri could be a single URI or a sequence
        if isinstance(uri, basestring):
            uri = [uri]

        for default_port in True, False:
            reduced_uri = tuple([self.reduce_uri(u, default_port) for u in uri])
            del self.passwd[reduced_uri][realm]


    def __contains__(self, uri):
        # uri could be a single URI or a sequence
        if isinstance(uri, basestring):
            uri = [uri]

        uri = tuple([self.reduce_uri(u, False) for u in uri])

        if uri in self.passwd:
            return True

        return False

auth_manager = AuthManager()



class AuthObject(object):
    """The :class:`AuthObject` is a simple HTTP Authentication token. When
    given to a Requests function, it enables Basic HTTP Authentication for that
    Request. You can also enable Authorization for domain realms with AutoAuth.
    See AutoAuth for more details.

    :param username: Username to authenticate with.
    :param password: Password for given username.
    :param realm: (optional) the realm this auth applies to
    :param handler: (optional) basic || digest || proxy_basic || proxy_digest
    """

    _handlers = {
        'basic': HTTPBasicAuthHandler,
        'forced_basic': HTTPForcedBasicAuthHandler,
        'digest': HTTPDigestAuthHandler,
        'proxy_basic': urllib2.ProxyBasicAuthHandler,
        'proxy_digest': urllib2.ProxyDigestAuthHandler
    }

    def __init__(self, username, password, handler='forced_basic', realm=None):
        self.username = username
        self.password = password
        self.realm = realm

        if isinstance(handler, basestring):
            self.handler = self._handlers.get(handler.lower(), HTTPForcedBasicAuthHandler)
        else:
            self.handler = handler
