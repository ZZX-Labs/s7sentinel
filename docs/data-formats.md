# Data Formats

## PLC inventory CSV

Required column: `ip`.

Recognized columns:

```text
ip,asset_name,model,firmware,network_zone,internet_exposed,remote_access,mfa,patch_status,gold_copy_verified,engineering_access_restricted,plc_password,protection_level,snmp_hardened,app_allowlisting,logging_enabled,web_server_disabled,unused_protocols_disabled,connection_limits,restart_protection,know_how_protection,logic_integrity_verified,vendor_support_verified,notes
```

Each row must contain a unique IPv4 address. Invalid or duplicate addresses fail the run.

## S7 event CSV

Required columns:

```text
timestamp,src_ip,dst_ip,dst_port,operation,authorized_source,change_ticket
```

Timestamps must be ISO-8601. `authorized_source` accepts common boolean forms such as `yes/no` and `true/false`.

## Agentic identity/web/API event CSV

Required columns:

```text
timestamp,src_ip,event
```

Recommended full schema:

```text
timestamp,src_ip,user,system,event,endpoint,status,auth_result,auth_method,jwt_alg,bytes_out,file_name,user_agent,authorized,sensitive,change_ticket
```

Field semantics:

- `timestamp`: ISO-8601 timestamp.
- `src_ip`: observed source address from trusted telemetry.
- `user`: normalized identity if known.
- `system`: logical application/system name.
- `event`: event class such as `login`, `api_request`, `file_upload`, `export`.
- `endpoint`: normalized URL/API path when available.
- `status`: HTTP/application numeric status when applicable.
- `auth_result`: `success`, `failed`, `denied`, or equivalent.
- `auth_method`: `password`, `mfa`, `sso`, `session`, `anonymous`, `none`, etc.
- `jwt_alg`: observed JWT algorithm metadata if your gateway safely records it.
- `bytes_out`: response/egress size represented by the event.
- `file_name`: uploaded object name when logged.
- `user_agent`: normalized client agent string.
- `authorized`: whether the source/action is known approved activity.
- `sensitive`: whether the resource is classified as sensitive by local policy.
- `change_ticket`: local change identifier when applicable.

Do not place passwords, tokens, session cookies, private keys, or full sensitive response bodies in these files.
