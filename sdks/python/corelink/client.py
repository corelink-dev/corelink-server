"""CoreLink synchronous HTTP client.

Control-plane operations (derived from openapi-corelink-v1.yaml):

  Operation      | operationId | Method | Path
  -------------- | ----------- | ------ | ---------------------
  Health probe   | apiHealth   | GET    | /api/health
  Issue PAT      | patIssue    | POST   | /v1/pats
  Tenant signup  | signup      | POST   | /v1/signup

CAS data-plane operations (native BLAKE3-keyed routes, tenant-scoped):

  Operation      | Method | Path
  -------------- | ------ | ---------------------------
  Put blob       | PUT    | /v1/cas/{tenant}/{digest}
  Get blob       | GET    | /v1/cas/{tenant}/{digest}
  Stat blob      | HEAD   | /v1/cas/{tenant}/{digest}

Auth: Bearer PAT via ``Authorization: Bearer <token>`` header
      (BearerPAT security scheme).

This client is synchronous. The async surface documented in the how-to guides
(``async with`` / ``await client.put(...)``) lives in
:class:`corelink.aio.AsyncCoreLinkClient`.
"""

from __future__ import annotations

import os
from typing import IO

import httpx

from ._errors import raise_for_cas_status, raise_for_control_status
from .cas import (
    DEFAULT_CHUNK_SIZE,
    StatResult,
    hash_stream,
    iter_file,
    resolve_put_digest,
    validate_digest,
    verify_bytes,
)
from .types import (
    HealthResponse,
    PatIssueRequest,
    PatIssueResponse,
    SignupRequest,
    SignupResponse,
)

# Canonical flat prod host (`corelink-*.humangr.com`). NOTE: the dotted
# `*.corelink.humangr.com` pattern is DEAD — the previous default, the
# dotted `api.` name under it, never resolved.
_DEFAULT_BASE_URL = "https://corelink-api.humangr.com"
_DEFAULT_TIMEOUT = 30.0


class CoreLinkClient:
    """Synchronous CoreLink REST API client.

    Parameters
    ----------
    pat:
        Personal Access Token.  If *None*, the value of the
        ``CORELINK_PAT`` environment variable is used.  Raises
        :class:`ValueError` if neither is provided.
    tenant_id:
        Tenant scope for all CAS data-plane operations (``put`` / ``get`` /
        ``stat``).  Optional — control-plane calls (health / issue_pat /
        signup) do not need it, but a CAS call without a tenant raises
        :class:`ValueError`.
    base_url:
        Override the server base URL (useful for staging / local dev).
        Defaults to ``https://corelink-api.humangr.com``.
    timeout:
        Request timeout in seconds.  Defaults to 30.

    Examples
    --------
    >>> client = CoreLinkClient(pat="ct_xxx")
    >>> health = client.get_health()
    >>> health.status.value
    'SERVING'
    >>> cas = CoreLinkClient(pat="ct_xxx", tenant_id="acme-corp")
    >>> digest = cas.put(b"hello world")  # 64-char BLAKE3 hex
    """

    def __init__(
        self,
        pat: str | None = None,
        *,
        tenant_id: str | None = None,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        resolved_pat = pat or os.environ.get("CORELINK_PAT")
        if not resolved_pat:
            raise ValueError(
                "CoreLink PAT must be supplied via `pat=` argument or "
                "the CORELINK_PAT environment variable."
            )
        self._pat: str = resolved_pat
        self._tenant_id: str | None = tenant_id
        self._base_url: str = base_url.rstrip("/")
        self._http: httpx.Client = httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {self._pat}"},
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> CoreLinkClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _raise_for_status(self, response: httpx.Response) -> None:
        """Raise an appropriate SDK exception for a control-plane response.

        Does nothing for 2xx responses.
        """
        raise_for_control_status(response)

    def _raise_for_cas_status(self, response: httpx.Response) -> None:
        """Raise an appropriate SDK exception for a CAS data-plane response.

        Does nothing for 2xx responses.
        """
        raise_for_cas_status(response)

    def _cas_url(self, digest: str) -> str:
        """Build the tenant-scoped CAS object URL, failing fast on a missing
        tenant or a malformed digest."""
        if not self._tenant_id:
            raise ValueError(
                "CAS operations require a tenant; construct the client with "
                "`tenant_id=`."
            )
        return f"/v1/cas/{self._tenant_id}/{validate_digest(digest)}"

    # ------------------------------------------------------------------
    # CAS data-plane operations (BLAKE3-keyed)
    # ------------------------------------------------------------------

    def put(self, data: bytes, *, expected_digest: str | None = None) -> str:
        """Store *data* in the CAS and return its 64-char BLAKE3 hex digest.

        ``PUT /v1/cas/{tenant}/{digest}`` — idempotent on the digest (a second
        put of identical bytes returns the same digest, no extra storage).

        Parameters
        ----------
        data:
            Raw bytes to store.
        expected_digest:
            A precomputed BLAKE3 digest to key the blob under, skipping local
            recomputation. Format-validated locally; a value that does not
            match the bytes is rejected by the server (422 →
            :class:`CoreLinkDigestMismatchError`).

        Raises
        ------
        CoreLinkDigestMismatchError, CoreLinkQuotaError, CoreLinkAuthError,
        CoreLinkRequestError, CoreLinkServerError
        """
        digest = resolve_put_digest(data, expected_digest)
        response = self._http.put(self._cas_url(digest), content=data)
        self._raise_for_cas_status(response)
        return digest

    def put_stream(
        self,
        fileobj: IO[bytes],
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        expected_digest: str | None = None,
    ) -> str:
        """Stream a (large) blob from a binary file without buffering it whole.

        The BLAKE3 digest is computed in one seek-rewind pass over *fileobj*
        (unless *expected_digest* is supplied), then the same handle is streamed
        to ``PUT /v1/cas/{tenant}/{digest}`` in ``chunk_size`` chunks.

        Parameters
        ----------
        fileobj:
            A seekable binary file (``open(path, "rb")``).
        chunk_size:
            Read / upload chunk size in bytes (default 4 MiB).
        expected_digest:
            Skip the hashing pass and key the blob under this precomputed
            digest (format-validated locally; verified server-side).
        """
        if expected_digest is not None:
            digest = validate_digest(expected_digest)
        else:
            digest = hash_stream(fileobj, chunk_size)
        response = self._http.put(
            self._cas_url(digest), content=iter_file(fileobj, chunk_size)
        )
        self._raise_for_cas_status(response)
        return digest

    def get(self, digest: str, *, verify: bool = True) -> bytes:
        """Download a blob by BLAKE3 hex digest.

        ``GET /v1/cas/{tenant}/{digest}``. With *verify* (default) the returned
        bytes are re-hashed client-side (CTRL-CAS-002) and a mismatch raises
        :class:`CoreLinkDigestMismatchError` — corrupted bytes never reach the
        caller as valid data.

        Raises
        ------
        CoreLinkNotFoundError, CoreLinkDigestMismatchError, CoreLinkAuthError,
        CoreLinkRequestError, CoreLinkServerError
        """
        url = self._cas_url(digest)
        response = self._http.get(url)
        self._raise_for_cas_status(response)
        data = response.content
        if verify:
            verify_bytes(digest, data)
        return data

    def stat(self, digest: str) -> StatResult:
        """Return metadata for a blob without downloading it.

        ``HEAD /v1/cas/{tenant}/{digest}`` (axum serves HEAD for the GET route):
        200 → present (``size_bytes`` from ``Content-Length``); 404 / 410 →
        absent. Any other status raises.
        """
        url = self._cas_url(digest)
        response = self._http.head(url)
        if response.status_code in (404, 410):
            return StatResult(digest=digest, size_bytes=0, exists=False)
        self._raise_for_cas_status(response)
        size = int(response.headers.get("content-length", "0") or "0")
        return StatResult(digest=digest, size_bytes=size, exists=True)

    # ------------------------------------------------------------------
    # Control-plane operations
    # ------------------------------------------------------------------

    def get_health(self) -> HealthResponse:
        """Liveness / readiness probe.

        operationId: **apiHealth** — ``GET /api/health``

        Returns
        -------
        HealthResponse
            Server health status.  Does **not** require authentication.

        Raises
        ------
        CoreLinkServerError
            If the server returns a 5xx response.
        """
        response = self._http.get("/api/health")
        self._raise_for_status(response)
        return HealthResponse.model_validate(response.json())

    def issue_pat(self, request: PatIssueRequest) -> PatIssueResponse:
        """Issue a new Personal Access Token (shown once).

        operationId: **patIssue** — ``POST /v1/pats``

        Parameters
        ----------
        request:
            PAT creation parameters (label + optional scopes / expiry).

        Returns
        -------
        PatIssueResponse
            Newly issued PAT metadata **including** the raw token material
            (``shown_once_token``).  Store it securely — it will not be
            retrievable again.

        Raises
        ------
        CoreLinkAuthError
            If the PAT is missing or invalid.
        CoreLinkRequestError
            For 4xx errors (e.g. 422 Unprocessable).
        CoreLinkServerError
            For 5xx server errors.
        """
        response = self._http.post(
            "/v1/pats",
            json=request.model_dump(exclude_none=True),
        )
        self._raise_for_status(response)
        return PatIssueResponse.model_validate(response.json())

    def signup(
        self,
        request: SignupRequest,
        *,
        idempotency_key: str | None = None,
    ) -> SignupResponse:
        """Provision a new tenant from a verified Clerk identity.

        operationId: **signup** — ``POST /v1/signup``

        This is the atomic onboarding orchestration endpoint: tenant row +
        DPA acceptance + first PAT issuance in a single D1 transaction
        (INV-ONBOARD-ATOMIC-PROVISIONING).

        Parameters
        ----------
        request:
            Signup payload.  ``email_hash`` **must** be the SHA-256 hex of
            the normalised email address — raw email is never transmitted
            (CTRL-PRIV-001).
        idempotency_key:
            Optional override for the ``Idempotency-Key`` header.  If
            *None*, ``request.idempotency_key`` is used.

        Returns
        -------
        SignupResponse
            Signup outcome including the first PAT (shown once) and
            assigned tenant ID.

        Raises
        ------
        CoreLinkAuthError
            If the PAT is missing or invalid.
        CoreLinkRequestError
            For 4xx errors (e.g. 409 Conflict on duplicate signup,
            422 Unprocessable).
        CoreLinkServerError
            For 5xx server errors.
        """
        idem_key = idempotency_key or request.idempotency_key
        response = self._http.post(
            "/v1/signup",
            json=request.model_dump(exclude_none=True),
            headers={
                "Idempotency-Key": idem_key,
                "X-Correlation-Id": request.correlation_id,
            },
        )
        self._raise_for_status(response)
        return SignupResponse.model_validate(response.json())
