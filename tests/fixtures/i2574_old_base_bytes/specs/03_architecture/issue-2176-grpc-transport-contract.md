# Issue #2176 gRPC transport contract

**BLOCKED — no public gRPC claim.**

`application/grpc` is rejected at the first statement of the public Worker
Fetch handler before routing, Durable Object lookup, Container startup, or a
Container `getTcpPort(50051)` Fetch proxy.

Removing that denial requires a separately reviewed, protected-environment
runtime receipt for the exact deployed SHA and endpoint. It must prove an
external HTTP/2 gRPC request through Worker → Durable Object → Container over a
raw TCP socket, preserving binary framing, authorization metadata, response
metadata, `grpc-status`, trailers, cancellation, unary behavior, and streaming
behavior.

No REST, HTTP/1, gRPC-Web, local proxy, or local cache fallback.
