# technocore-signed-pointer-content-hash-binding-verifier

Signed-pointer content-hash binding verifier for off-chain Technocore contributions.

Problem: guides are shared as signed pointers to off-chain readable posts.
A signature over a link still verifies after the post is edited or deleted.
Readers cannot tell if the text they see is the text that was signed.

This tool checks binding between a signed pointer and the current off-chain body
using an embedded SHA-256 content hash.

Features
- Read-only fetch of public article bodies with SHA-256 of normalized text.
- Parse of signed payload for embedded content hash.
- Status report: MATCH, MISMATCH, MISSING-HASH, UNREACHABLE.
- Drift detection across re-checks with length and line summary.
- Auditable JSON plus human-readable Markdown report.
- Batch verify from a local JSON file with caching and retries.
- Author guidance and canonical normalization spec.

No secrets: the tool never asks for private keys, wallets, or credentials.
It only reads public URLs and local files.

Statuses
- MATCH: observed hash equals embedded hash.
- MISMATCH: observed hash differs; likely silent edit or wrong body.
- MISSING-HASH: payload has no usable 64-char hex hash.
- UNREACHABLE: fetch failed, login wall, rate limit, or deleted post.

Normalization spec norm-v1
1. Unescape HTML entities.
2. If text looks like HTML, strip script, style, and tags to spaces.
3. Convert CRLF and CR to LF.
4. Trim trailing spaces and tabs on each line.
5. Collapse 3 or more newlines to 2.
6. Trim leading and trailing blank lines and spaces.
7. Hash UTF-8 bytes of normalized text with SHA-256, lowercase hex.

Author guidance: how to bind at signing time
1. Prepare final article text.
2. Normalize with norm-v1 steps above.
3. Compute SHA-256 hex of normalized UTF-8.
4. Embed as content_hash in the signed payload with url, did, and signed_at.
5. Sign the payload. Any later edit will cause MISMATCH unless you sign a new hash.

Usage
- Requires Python 3.10 or later, standard library only.
- Run tests: python -m unittest discover -v
- Single check via Python: import verifier, then hash_content and verify_one.
- Batch check: python cli.py --payloads payloads.json --out-json report.json --cache cache.json

payloads.json format: a JSON list of objects.
Each object needs url and content_hash, plus optional did and signed_at.
Example entry fields: url, content_hash, did, signed_at.
See cli help: python cli.py --help

Caching and retries
- cache.json stores last observed hash per URL to flag drift on next run.
- --retries sets extra tries per URL, --delay sets seconds between tries.
- Be kind to hosts: keep retries low and reuse cache.

Limitations
- Point-in-time observation with normalization version recorded.
- Fetch may fail on login walls, rate limits, or script-rendered pages.
- Hash proves binding only if author embedded a hash; it does not prove authorship truth.
- A new signature over altered text will still show MATCH for the new hash.
- Deletion shows as UNREACHABLE, not as proof of removal.

License: MIT.
