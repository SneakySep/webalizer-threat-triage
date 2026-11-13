"""Consistent API error envelopes and exception handlers."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


class AppError(Exception):
    """An expected application error with a safe public representation."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        details: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers


def error_payload(
    code: str,
    message: str,
    details: Any | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    if request_id:
        error["request_id"] = request_id
    return {"error": error}


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_payload(
                exc.code,
                exc.message,
                exc.details,
                request_id=_request_id(request),
            ),
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        details = [
            {
                "loc": list(error.get("loc", ())),
                "message": error.get("msg", "invalid value"),
                "type": error.get("type", "value_error"),
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=error_payload(
                "VALIDATION_ERROR",
                "Request validation failed",
                details,
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        code = "NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR"
        detail = exc.detail if isinstance(exc.detail, str) else "HTTP error"
        return JSONResponse(
            status_code=exc.status_code,
            content=error_payload(
                code,
                detail,
                request_id=_request_id(request),
            ),
            headers=exc.headers,
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "Unhandled API error for %s %s",
            request.method,
            request.url.path,
            exc_info=exc,
        )
        return JSONResponse(
            status_code=500,
            content=error_payload(
                "INTERNAL_ERROR",
                "An unexpected server error occurred",
                request_id=_request_id(request),
            ),
        )
