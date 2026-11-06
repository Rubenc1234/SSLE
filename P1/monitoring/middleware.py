
"""
Flask middleware for Prometheus instrumentation.

Automatically collects:
- HTTP request count
- HTTP request duration
- HTTP response status codes
- Request body size on the Ingestion /ingest endpoint

Usage:
    from monitoring.middleware import instrument_app
    instrument_app(app)
"""

import time

from flask import g, request

from monitoring.metrics import (
    HTTP_REQUESTS_TOTAL,
    HTTP_REQUEST_DURATION_SECONDS,
    REQUEST_BODY_SIZE_BYTES,
)


def instrument_app(app):
    """
    Register Prometheus instrumentation hooks on a Flask application.

    Call exactly once per Flask app, after creating the app.
    """

    @app.before_request
    def prometheus_before_request():
        g.prometheus_metrics_recorded = False
        # Start measuring request duration
        g.prometheus_start_time = time.perf_counter()

        # Use the logical route, not the interpolated URL.
        # Example: /services/<service_name>
        if request.url_rule is not None:
            g.prometheus_endpoint = request.url_rule.rule
        else:
            g.prometheus_endpoint = request.endpoint or "unknown"

        # Branch A: measure request body size on Ingestion.
        # get_data(cache=True) preserves the body for later JSON parsing.
        if request.path == "/ingest":
            body = request.get_data(cache=True)
            REQUEST_BODY_SIZE_BYTES.observe(len(body))

    @app.after_request
    def prometheus_after_request(response):

        if not g.prometheus_metrics_recorded:

            endpoint = getattr(g, "prometheus_endpoint", "unknown")
            method = request.method
            status = str(response.status_code)

            HTTP_REQUESTS_TOTAL.labels(
                method=method,
                endpoint=endpoint,
                status=status,
            ).inc()

            start_time = getattr(g, "prometheus_start_time", None)

            if start_time is not None:
                duration = time.perf_counter() - start_time

                HTTP_REQUEST_DURATION_SECONDS.labels(
                    method=method,
                    endpoint=endpoint,
                ).observe(duration)

            g.prometheus_metrics_recorded = True

        return response


    @app.teardown_request
    def prometheus_teardown_request(exception):

        if g.get("prometheus_metrics_recorded", False):
            return

        endpoint = getattr(g, "prometheus_endpoint", "unknown")
        method = request.method

        # An unhandled exception means the request failed.
        status = "500" if exception is not None else "500"

        HTTP_REQUESTS_TOTAL.labels(
            method=method,
            endpoint=endpoint,
            status=status,
        ).inc()

        start_time = getattr(g, "prometheus_start_time", None)

        if start_time is not None:
            duration = time.perf_counter() - start_time

            HTTP_REQUEST_DURATION_SECONDS.labels(
                method=method,
                endpoint=endpoint,
            ).observe(duration)

        g.prometheus_metrics_recorded = True
