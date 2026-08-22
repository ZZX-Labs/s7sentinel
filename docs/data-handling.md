# Data Handling and Privacy

S7Sentinel does not include a cloud service, tracking library, analytics endpoint, remote database, update beacon, or phone-home mechanism.

All supplied inventories, logs, file paths, hashes, and generated reports remain on the system where the program runs unless the operator moves them elsewhere.

Security telemetry can itself be sensitive. Recommended handling practices include least-privilege access, encrypted storage, short-lived working copies, sanitization before issue submission, and avoiding secrets in normalized CSV fields.

Do not attach real customer logs or sensitive PLC inventories to public bug reports.
