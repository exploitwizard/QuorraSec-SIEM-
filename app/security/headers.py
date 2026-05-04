# app/security/headers.py — OWASP A05: Security Misconfiguration
import os
import logging
from flask import request, jsonify, redirect, url_for

logger = logging.getLogger(__name__)

_CACHE_CONTROLLED_PATHS = ('/api/', '/login', '/dashboard', '/register')


def apply_security_headers(app):
    """Register enhanced security headers on all responses."""

    @app.after_request
    def _security_headers(response):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = (
            'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
        )
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' wss: ws:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none';"
        )
        if os.environ.get('TLS_ENABLED', 'false').lower() == 'true':
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains'
            )
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)
        if any(request.path.startswith(p) for p in _CACHE_CONTROLLED_PATHS):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response

    _register_error_handlers(app)


def _register_error_handlers(app):
    @app.errorhandler(400)
    def _bad_request(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Bad request'}), 400
        return 'Bad Request', 400

    @app.errorhandler(401)
    def _unauthorized(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Authentication required'}), 401
        return redirect(url_for('login'))

    @app.errorhandler(403)
    def _forbidden(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Access denied'}), 403
        return 'Forbidden', 403

    @app.errorhandler(404)
    def _not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not found'}), 404
        return 'Not Found', 404

    @app.errorhandler(429)
    def _rate_limited(e):
        return jsonify({'error': 'Too many requests', 'retry_after': 60}), 429

    @app.errorhandler(500)
    def _server_error(e):
        logger.error("500 error: %s path=%s ip=%s", e, request.path, request.remote_addr, exc_info=True)
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error'}), 500
        return 'Internal Server Error', 500
