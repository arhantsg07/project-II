# Indicator matching notes

The `iocs` table stores exact-value IP, domain, and hash indicators, along
with their source, confidence, optional context, and optional expiry. The
detector currently checks IP and domain entities attached to normalized
events; hash matching is reserved until the event schema exposes file
hashes. Expired indicators are ignored. Matching is exact and case-sensitive
for domains, so feed imports should normalize domain values consistently.

Confidence (`low`, `medium`, `high`) is copied to the alert and mapped to
the same alert severity. Rule-based alerts and IOC alerts are independent:
one event may produce either or both. Uniqueness on `(ioc_type, value)`
keeps seed imports repeatable; a future feed importer should explicitly
update source, confidence, context, and expiry when a feed refreshes an
existing value.

`lab/iocs/seed.sql` uses reserved TEST-NET addresses and synthetic `.test`
domains only. It demonstrates the schema and matching path, not a live
threat-intelligence feed. A production integration would need feed
provenance, normalization, licensing review, refresh/expiry policy, and
auditing for IOC changes.
