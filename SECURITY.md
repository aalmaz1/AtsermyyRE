# Security Policy

This repository contains a static analysis write-up of a malicious Android application.

- The APK sample is **not** distributed here. Do not open issues asking for the sample.
- IOCs are published defanged (`opppi[.]com`) — please keep them that way if you reuse them.
- No victim PII and no working credentials are published. Secrets found in the binary
  are redacted or reduced to non-functional fragments.

## Reporting

If you received a similar APK or are a victim of this campaign, **do not install or run it**.
For responsible disclosure, corrections to this analysis, or to report an IOC that is
still live:

- Open a GitHub issue (for non-sensitive corrections), or
- Contact the author via the GitHub profile: [@aalmaz1](https://github.com/aalmaz1)

Please include the SHA-256 of the sample and, if possible, the distribution channel
(messenger, dating app, etc.). Reports of live infrastructure will be forwarded to the
hosting provider and to the relevant platform's abuse team.
