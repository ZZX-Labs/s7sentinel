# FAQ

## Does S7Sentinel exploit PLCs?

No. The active scanner performs TCP reachability only.

## Does it use python-snap7?

No. It can detect Snap7-related artifacts, but it does not import Snap7 or use it to communicate with controllers.

## Can it scan the public Internet?

No. Non-RFC1918 CIDR expansion is refused. Individually supplied non-RFC1918 addresses require explicit authorization flags.

## Does the Dream-derived profile attack web applications?

No. It analyzes local artifacts and supplied logs only.

## Why not automatically identify every CVE?

Industrial vulnerability applicability is model, firmware, configuration, and sometimes feature specific. The core project avoids speculative attribution. Operators can load verified local advisory rules.

## Can a clean report prove a system is uncompromised?

No. S7Sentinel is one defensive evidence source within a broader monitoring and incident-response program.
