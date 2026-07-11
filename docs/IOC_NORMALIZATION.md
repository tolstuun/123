# IOC Normalization

Original values are always retained. Hashes are lowercase after strict length/hex validation. IPv4 and IPv6 use canonical compressed address formatting. Domains and email domain parts are lowercase, stripped of a trailing dot, and IDNA encoded. URLs lowercase scheme/host, remove default ports, normalize an empty path to `/`, and preserve query ordering and fragments. Windows paths convert `/` to `\`, collapse duplicate separators, and lowercase drive letters and path text. Filenames use Unicode NFKC and lowercase. Unknown types use trimmed Unicode NFKC text.

An IOC is actionable when its normalized verdict is malicious or suspicious, or explicit source context marks it actionable; unclassified and known low-value context remain non-actionable.
