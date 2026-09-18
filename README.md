# nvlx: Linux-NVIDIA-Driver v1.6.6.6.6.6.6.6.6.6.3.3.1.2.3.4.5.6.7.5.6.7.8.5.1.2.3.4.5.6.7.2

`nvlx` v1.6.6.6.6.6.6.6.6.6.3.3.1.2.3.4.5.6.7.5.6.7.8.5.1.2.3.4.5.6.7.2 adds `Grpc-Trace-Bin` Connection-nomination containment to the live HTTP surface after the inherited Grpc-Retry-Pushback-Ms gate.

> [!IMPORTANT]
> NVIDIA driver/GPU Operator resources remain read-only. The operator still mutates only nvlx-owned GPUFleet status/finalizers plus its existing Lease and Events.

## v1.6.6.6.6.6.6.6.6.6.3.3.1.2.3.4.5.6.7.5.6.7.8.5.1.2.3.4.5.6.7.2 Grpc-Trace-Bin Connection-nomination containment

- Exact `grpc-trace-bin` Connection options are rejected case-insensitively with terminal `400 Request Rejected` before runtime evaluation.
- Ordinary `Grpc-Trace-Bin` fields and substring lookalikes remain admissible. Values remain opaque, including empty and non-Base64 values permitted by inherited HTTP grammar.
- [OpenCensus gRPC tracing](https://github.com/census-instrumentation/opencensus-go/blob/master/plugin/ocgrpc/trace_common.go) uses this metadata for serialized trace context. Trace parsing and propagation remain external to this HTTP containment layer.
- Grpc-Retry-Pushback-Ms and all earlier gates retain precedence, including canonical `417` rejection for `Expect`.
- HEAD rejection remains bodyless; pipeline termination, runtime isolation, and worker capacity recovery are preserved.
- Ingress budgets remain 8 KiB request lines, 32 KiB headers, 32 fields, 5-second idle timeout and absolute header deadline, and 32 concurrent requests.
- The live operator uses `http_v166666666633112345675678512344565672` with `runtime_v1664`. Checkpoint persistence, metrics, RBAC, readiness policy, and NVIDIA read-only behavior are preserved.

## Ingress resource model

1. `max_concurrent_requests` — default 32.
2. `request_timeout_seconds` — default 5 seconds.
3. `request_header_deadline_seconds` — default 5 seconds.
4. `max_request_line_bytes` — default 8192 bytes.
5. `max_request_header_bytes` — default 32768 bytes.
6. `max_request_header_fields` — default 32 fields.

Protocol invariants remain fail-closed in the inherited order: request framing and target syntax; header grammar and value-octet containment; `Expect`; upgrade/Trailer/TE/Proxy-Connection; canonical Connection parsing/lifecycle/critical nomination/duplication/singleton enforcement; Keep-Alive/HTTP2-Settings/WebSocket/Proxy-Authorization; Authorization/Cookie/Forwarded and forwarding/client-IP nomination containment; Envoy external/original/internal/attempt/decorator/timeout metadata; `X-Envoy-Retry-On`; `X-Envoy-Retry-Grpc-On`; `X-Envoy-Max-Retries`; `X-Envoy-Hedge-On-Per-Try-Timeout`; `X-Envoy-Retriable-Header-Names`; `X-Envoy-Retriable-Status-Codes`; `X-Envoy-Upstream-Alt-Stat-Name`; `X-Envoy-Upstream-Rq-Timeout-Alt-Response`; `X-Envoy-Is-Timeout-Retry`; `X-Envoy-Original-Host`; `X-Envoy-Upstream-Stream-Duration-Ms`; `X-Envoy-Downstream-Service-Cluster`; `X-Envoy-Downstream-Service-Node`; `X-Envoy-Force-Trace`; `X-Envoy-IP-Tags`; `X-Forwarded-Client-Cert`; `X-Request-ID`; `X-Client-Trace-ID`; `X-OT-Span-Context`; `X-B3-TraceId`; `X-B3-SpanId`; `X-B3-ParentSpanId`; `X-B3-Sampled`; `X-B3-Flags`; `B3`; `X-Datadog-Trace-ID`; `X-Datadog-Parent-ID`; `X-Datadog-Sampling-Priority`; `SW8`; `X-Amzn-Trace-Id`; `Traceparent`; `Tracestate`; `X-Envoy-Local-Overloaded`; `Referer`; `User-Agent`; `X-Envoy-Original-Method`; `X-Envoy-Peer-Metadata`; `X-Envoy-Peer-Metadata-ID`; `X-Envoy-Auth-Partial-Body`; `X-Envoy-OAuth-Status`; `X-Envoy-OAuth-Failure-Reason`; `Grpc-Timeout`; `Grpc-Previous-Rpc-Attempts`; `Grpc-Encoding`; `Grpc-Accept-Encoding`; `Grpc-Message-Type`; `Content-Type`; `Grpc-Status`; `Grpc-Message`; `Grpc-Status-Details-Bin`; `Grpc-Retry-Pushback-Ms`; then `Grpc-Trace-Bin`.

## Safety invariants

1. CPython legacy headerless parser representation is accepted only when it is an exact empty mapping.
2. HTTP/0.9 and unsupported/non-canonical HTTP/1.x requests are rejected before endpoint/runtime evaluation.
3. HTTP/1.1 requires exactly one valid non-empty Host authority.
4. Raw request targets must survive parsing unchanged and begin with exactly one `/`.
5. Absolute/authority/asterisk forms, fragments, backslashes, controls, and raw non-ASCII target bytes are rejected.
6. Percent escapes must contain exactly two ASCII hex digits.
7. Obsolete folded request headers are rejected.
8. Physical header names must use strict ASCII token grammar and be followed immediately by `:`.
9. Physical field values are limited to HTAB, SP, and visible ASCII.
10. Any `Expect` field is rejected with canonical terminal 417 framing and no `100 Continue`.
11. Request-line token separators must reconstruct canonically with single ASCII spaces.
12. Request/header lines and the blank terminator must use CRLF.
13. `Upgrade` fields and exact `upgrade` Connection tokens are rejected.
14. Request `Trailer` declarations are rejected.
15. Request `TE` fields and exact `te` Connection tokens are rejected.
16. `Proxy-Connection` fields and exact `proxy-connection` Connection tokens are rejected.
17. Remaining Connection fields must be non-empty comma-separated ASCII token lists.
18. Connection lifecycle conflicts between `close` and `keep-alive` are rejected.
19. Connection options may not nominate Host, Content-Length, Transfer-Encoding, Trailer, Expect, or Connection.
20. Remaining Connection options may appear only once case-insensitively.
21. At most one physical Connection field may remain after inherited gates succeed.
22. Physical Keep-Alive request fields are rejected.
23. HTTP2-Settings request fields and exact nominations are rejected.
24. `Sec-WebSocket-*` request fields are rejected.
25. Proxy-Authorization request fields and exact nominations are rejected.
26. Exact `authorization` nomination is rejected while ordinary Authorization remains admissible when otherwise valid.
27. Exact `cookie` nomination is rejected while ordinary Cookie remains admissible when otherwise valid.
28. Exact `forwarded` nomination is rejected while ordinary Forwarded remains admissible when otherwise valid.
29. Exact `x-forwarded-for` nomination is rejected.
30. Exact `x-forwarded-host` nomination is rejected.
31. Exact `x-forwarded-proto` nomination is rejected.
32. Exact `x-forwarded-port` nomination is rejected.
33. Exact `x-forwarded-prefix` nomination is rejected.
34. Exact `x-forwarded-ssl` nomination is rejected.
35. Exact `x-forwarded-server` nomination is rejected.
36. Exact `x-forwarded-uri` nomination is rejected.
37. Exact `x-original-uri` nomination is rejected.
38. Exact `x-original-url` nomination is rejected.
39. Exact `x-rewrite-url` nomination is rejected.
40. Exact `x-forwarded-scheme` nomination is rejected.
41. Exact `x-real-ip` nomination is rejected.
42. Exact `x-client-ip` nomination is rejected.
43. Exact `true-client-ip` nomination is rejected.
44. Exact `cf-connecting-ip` nomination is rejected.
45. Exact `x-cluster-client-ip` nomination is rejected.
46. Exact `fastly-client-ip` nomination is rejected.
47. Exact `fly-client-ip` nomination is rejected.
48. Exact `x-envoy-external-address` nomination is rejected.
49. Exact `x-envoy-original-dst-host` nomination is rejected.
50. Exact `x-envoy-original-path` nomination is rejected.
51. Exact `x-envoy-original-url` nomination is rejected.
52. Exact `x-envoy-internal` nomination is rejected.
53. Exact `x-envoy-attempt-count` nomination is rejected.
54. Exact `x-envoy-decorator-operation` nomination is rejected.
55. Exact `x-envoy-expected-rq-timeout-ms` nomination is rejected.
56. Exact `x-envoy-upstream-rq-timeout-ms` nomination is rejected.
57. Exact `x-envoy-upstream-rq-per-try-timeout-ms` nomination is rejected.
58. Exact `x-envoy-retry-on` nomination is rejected.
59. Exact `x-envoy-retry-grpc-on` nomination is rejected.
60. Exact `x-envoy-max-retries` nomination is rejected.
61. Exact `x-envoy-hedge-on-per-try-timeout` nomination is rejected.
62. Exact `x-envoy-retriable-header-names` nomination is rejected; ordinary `X-Envoy-Retriable-Header-Names` remains admissible when otherwise valid.
63. Exact `x-envoy-retriable-status-codes` nomination is rejected; ordinary `X-Envoy-Retriable-Status-Codes` remains admissible when otherwise valid.
64. Exact `x-envoy-upstream-alt-stat-name` nomination is rejected; ordinary `X-Envoy-Upstream-Alt-Stat-Name` remains admissible when otherwise valid.
65. Exact `x-envoy-upstream-rq-timeout-alt-response` nomination is rejected; ordinary `X-Envoy-Upstream-Rq-Timeout-Alt-Response` remains admissible when otherwise valid.
66. Exact `x-envoy-is-timeout-retry` nomination is rejected; ordinary `X-Envoy-Is-Timeout-Retry` remains admissible when otherwise valid.
67. Exact `x-envoy-original-host` nomination is rejected; ordinary `X-Envoy-Original-Host` remains admissible when otherwise valid.
68. Exact `x-envoy-upstream-stream-duration-ms` nomination is rejected; ordinary `X-Envoy-Upstream-Stream-Duration-Ms` remains admissible when otherwise valid.
69. Exact `x-envoy-downstream-service-cluster` nomination is rejected; ordinary `X-Envoy-Downstream-Service-Cluster` remains admissible when otherwise valid.
70. Exact `x-envoy-downstream-service-node` nomination is rejected; ordinary `X-Envoy-Downstream-Service-Node` remains admissible when otherwise valid.
71. Exact `x-envoy-force-trace` nomination is rejected; ordinary `X-Envoy-Force-Trace` remains admissible when otherwise valid.
72. Exact `x-envoy-ip-tags` nomination is rejected; ordinary `X-Envoy-IP-Tags` remains admissible when otherwise valid.
73. Exact `x-forwarded-client-cert` nomination is rejected; ordinary `X-Forwarded-Client-Cert` remains admissible when otherwise valid.
74. Exact `x-request-id` nomination is rejected; ordinary `X-Request-ID` remains admissible when otherwise valid.
75. Exact `x-client-trace-id` nomination is rejected; ordinary `X-Client-Trace-ID` remains admissible when otherwise valid.
76. Exact `x-ot-span-context` nomination is rejected; ordinary `X-OT-Span-Context` remains admissible when otherwise valid.
77. Exact `x-b3-traceid` nomination is rejected; ordinary `X-B3-TraceId` remains admissible when otherwise valid.
78. Exact `x-b3-spanid` nomination is rejected; ordinary `X-B3-SpanId` remains admissible when otherwise valid.
79. Exact `x-b3-parentspanid` nomination is rejected; ordinary `X-B3-ParentSpanId` remains admissible when otherwise valid.
80. Exact `x-b3-sampled` nomination is rejected; ordinary `X-B3-Sampled` remains admissible when otherwise valid.
81. Exact `x-b3-flags` nomination is rejected; ordinary `X-B3-Flags` remains admissible when otherwise valid.
82. Exact `b3` nomination is rejected; ordinary `B3` remains admissible when otherwise valid.
83. Exact `x-datadog-trace-id` nomination is rejected; ordinary `X-Datadog-Trace-ID` remains admissible when otherwise valid.
84. Exact `x-datadog-parent-id` nomination is rejected; ordinary `X-Datadog-Parent-ID` remains admissible when otherwise valid.
85. Exact `x-datadog-sampling-priority` nomination is rejected; ordinary `X-Datadog-Sampling-Priority` remains admissible when otherwise valid.
86. Exact `sw8` nomination is rejected; ordinary `SW8` remains admissible when otherwise valid.
87. Exact `x-amzn-trace-id` nomination is rejected; ordinary `X-Amzn-Trace-Id` remains admissible when otherwise valid.
88. Exact `traceparent` nomination is rejected; ordinary `Traceparent` remains admissible when otherwise valid.
89. Exact `tracestate` nomination is rejected; ordinary `Tracestate` remains admissible when otherwise valid.
90. Exact `x-envoy-local-overloaded` nomination is rejected; ordinary `X-Envoy-Local-Overloaded` remains admissible when otherwise valid.
91. Exact `referer` nomination is rejected; ordinary `Referer` remains admissible when otherwise valid.
92. Exact `user-agent` nomination is rejected; ordinary `User-Agent` remains admissible when otherwise valid.
93. Exact `x-envoy-original-method` nomination is rejected; ordinary `X-Envoy-Original-Method` remains admissible when otherwise valid.
94. Exact `x-envoy-peer-metadata` nomination is rejected; ordinary `X-Envoy-Peer-Metadata` remains admissible when otherwise valid.
95. Exact `x-envoy-peer-metadata-id` nomination is rejected; ordinary `X-Envoy-Peer-Metadata-ID` remains admissible when otherwise valid.
96. Exact `x-envoy-auth-partial-body` nomination is rejected; ordinary `X-Envoy-Auth-Partial-Body` remains admissible when otherwise valid.
97. Exact `x-envoy-oauth-status` nomination is rejected; ordinary `X-Envoy-OAuth-Status` remains admissible when otherwise valid.
98. Exact `x-envoy-oauth-failure-reason` nomination is rejected; ordinary `X-Envoy-OAuth-Failure-Reason` remains admissible when otherwise valid.
99. Exact `grpc-timeout` nomination is rejected; ordinary `Grpc-Timeout` remains admissible when otherwise valid.
100. Exact `grpc-previous-rpc-attempts` nomination is rejected; ordinary `Grpc-Previous-Rpc-Attempts` remains admissible when otherwise valid.
101. Exact `grpc-encoding` nomination is rejected; ordinary `Grpc-Encoding` remains admissible when otherwise valid.
102. Exact `grpc-accept-encoding` nomination is rejected; ordinary `Grpc-Accept-Encoding` remains admissible when otherwise valid.
103. Exact `grpc-message-type` nomination is rejected; ordinary `Grpc-Message-Type` remains admissible when otherwise valid.
104. Exact `content-type` nomination is rejected; ordinary `Content-Type` remains admissible when otherwise valid.
105. Exact `grpc-status` nomination is rejected; ordinary `Grpc-Status` remains admissible when otherwise valid.
106. Exact `grpc-message` nomination is rejected; ordinary `Grpc-Message` remains admissible when otherwise valid.
107. Exact `grpc-status-details-bin` nomination is rejected; ordinary `Grpc-Status-Details-Bin` remains admissible when otherwise valid.
108. Exact `grpc-retry-pushback-ms` nomination is rejected; ordinary `Grpc-Retry-Pushback-Ms` remains admissible when otherwise valid.
109. Exact `grpc-trace-bin` nomination is rejected; ordinary `Grpc-Trace-Bin` remains admissible when otherwise valid.
110. HEAD rejection remains bodyless while preserving representation `Content-Length`.
111. Rejected requests cannot process trailing pipelined bytes on the same connection.
112. Rejection releases bounded worker capacity.
113. Header field-count, aggregate header bytes, and request-line byte budgets remain independently enforced.
114. Silent and byte-trickle partial requests remain bounded by the inherited idle timeout and absolute parse deadline.
115. Existing client-abort, parser-error, logging, response-body, resource, and method containment remains unchanged.
116. All v1.6.5.x checkpoint receipt, reconciliation, and persistence semantics remain unchanged.
117. NVIDIA driver/GPU Operator resources remain read-only in v1.6.6.6.6.6.6.6.6.6.3.3.1.2.3.4.5.6.7.5.6.7.8.5.1.2.3.4.5.6.7.2.
