from django.conf import settings
from django.core import mail
from django.http import HttpResponsePermanentRedirect
import logging

class SSLifyMiddleware(object):
    """Force all requests to use HTTPs. If we get an HTTP request, we'll just
    force a redirect to HTTPs.

    .. note::
        This will only take effect if ``settings.DEBUG`` is False.

    .. note::
        You can also disable this middleware when testing by setting
        ``settings.SSLIFY_DISABLE`` to True
    """
    def process_request(self, request):
        logger = logging.getLogger('default')
        # disabled for test mode?
        if getattr(settings, 'SSLIFY_DISABLE', False) and \
                hasattr(mail, 'outbox'):
            return None

        criteria = [request.is_secure(),
        settings.DEBUG,
        request.META.get('X-Forwarded-Proto', 'http') == 'https'
        ]
        # proceed as normal
        if not any(criteria):
            path  = request.path
            exempt_urls = getattr(settings,'SSLIFY_EXEMPT_PATHS', [])
            if path in exempt_urls:
                return None
            else:
                url = request.build_absolute_uri(request.get_full_path())
                secure_url = url.replace('http://', 'https://')
                return HttpResponsePermanentRedirect(secure_url)
        else:
            return None