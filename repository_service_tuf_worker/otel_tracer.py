# repository_service_tuf_worker/otel_tracer.py
from functools import wraps
from typing import Any, Dict, Iterable
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

SENSITIVE_KEYS = {"password", "secret", "token", "apikey", "key", "credential", "authorization"}

def _scrub(value: Any) -> Any:
    try:
        s = str(value)
    except Exception:
        return "<non-serializable>"
    if len(s) > 500:
        return s[:500] + "...<truncated>"
    return s

def _scrub_kv(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in kwargs.items():
        if k.lower() in SENSITIVE_KEYS:
            out[k] = "<redacted>"
        else:
            out[k] = v if isinstance(v, (str, int, float, bool)) else _scrub(v)
    return out

def get_tracer(instrumentation_name: str = "repository_service_tuf_worker"):
    # If no SDK/provider is configured, the default no-op tracer is returned.
    return trace.get_tracer(instrumentation_name)

def trace_function(operation_name: str | None = None, record_args: bool = True):
    """
    Decorator for plain functions/methods in repository_service_tuf_worker.
    - Creates a span per invocation
    - Records args/kwargs (scrubbed) and length metrics if iterable
    - Records exceptions and sets error status
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            name = operation_name or f"{func.__module__}.{func.__name__}"

            with tracer.start_as_current_span(name) as span:
                try:
                    if record_args:
                        # Avoid dumping large args; record basic shapes
                        if args:
                            span.set_attribute("fn.args.count", len(args))
                            # Only record the first few args as string (scrubbed)
                            preview = []
                            for i, a in enumerate(args[:3]):
                                if isinstance(a, (str, int, float, bool)):
                                    preview.append(a)
                                elif isinstance(a, Iterable) and not isinstance(a, (str, bytes, dict)):
                                    try:
                                        preview.append(f"{type(a).__name__}(len={len(a)})")
                                    except Exception:
                                        preview.append(type(a).__name__)
                                else:
                                    preview.append(_scrub(a))
                            span.set_attribute("fn.args.preview", str(preview))

                        if kwargs:
                            span.set_attribute("fn.kwargs", str(_scrub_kv(kwargs)))

                    result = func(*args, **kwargs)

                    # Lightweight result annotation
                    if isinstance(result, (str, int, float, bool)):
                        span.set_attribute("fn.result", str(result))
                    elif isinstance(result, dict):
                        span.set_attribute("fn.result.type", "dict")
                        span.set_attribute("fn.result.size", len(result))
                    elif isinstance(result, Iterable) and not isinstance(result, (str, bytes, dict)):
                        try:
                            span.set_attribute("fn.result.type", type(result).__name__)
                            span.set_attribute("fn.result.size", len(result))  # may raise
                        except Exception:
                            span.set_attribute("fn.result.type", type(result).__name__)

                    span.set_status(Status(StatusCode.OK))
                    return result

                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise
        return wrapper
    return decorator
