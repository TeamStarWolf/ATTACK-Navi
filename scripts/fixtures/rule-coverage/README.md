# Rule-coverage parser fixtures

One unmodified rule file per upstream, read by `scripts/build-rule-coverage-snapshot.test.mjs`.
The test packs them into in-memory tarballs shaped like the ones codeload.github.com
serves, so the tar reader and the three parsers run without the network.

| File | Upstream path | Commit | Licence |
| --- | --- | --- | --- |
| `elastic-rule.toml` | elastic/detection-rules `rules/windows/collection_email_outlook_mailbox_via_com.toml` | `7115bb0ab06c11c7994486ffe2bc0dc801ad8502` | Elastic License 2.0 |
| `splunk-detection.yml` | splunk/security_content `detections/endpoint/7zip_commandline_to_smb_share_path.yml` | `678e76c5f36f6fadd93a1eaa0d82c1dbe273c486` | Apache License 2.0 |
| `mdecrevoisier-rule.yaml` | mdecrevoisier/SIGMA-detection-rules `windows-active_directory/win-ad-kerberoast ticket detected.yaml` | `d61408af8769c74c96296b7ccc92d4bc3abb15af` | CC0 1.0 Universal |

Each file keeps its upstream licence and is redistributed here under it, unmodified; they
are test inputs and are not shipped in the app. The licence terms travel with them in
`licenses/`, copied verbatim from each repository at the commit above:

- `elastic-rule.toml`: Copyright Elasticsearch B.V., licensed under the Elastic License 2.0.
  Terms: [`licenses/elastic-detection-rules-LICENSE.txt`](licenses/elastic-detection-rules-LICENSE.txt)
  (upstream `LICENSE.txt`, also at https://www.elastic.co/licensing/elastic-license); the
  repository's notices: [`licenses/elastic-detection-rules-NOTICE.txt`](licenses/elastic-detection-rules-NOTICE.txt)
  (upstream `NOTICE.txt`; this rule, `1dee0500-4aeb-44ca-b24b-4a285d7b6ba1`, is not one of the
  third-party-derived rules it lists).
- `splunk-detection.yml`: from splunk/security_content, licensed under the Apache License,
  Version 2.0. Terms: [`licenses/splunk-security_content-LICENSE`](licenses/splunk-security_content-LICENSE)
  (upstream `LICENSE`, also at https://www.apache.org/licenses/LICENSE-2.0). The repository
  has no `NOTICE` file at that commit.
- `mdecrevoisier-rule.yaml`: dedicated to the public domain under CC0 1.0 Universal
  (https://creativecommons.org/publicdomain/zero/1.0/); no terms need to accompany it.
