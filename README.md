# Verified ClamAV definition delivery

Infrastructure-only mirror for unmodified, signed public ClamAV CVD files. No application source, customer documents, credentials or private data belong here.

## Plan and impact (Issue 1)

An isolated GitHub-hosted job uses the official digest-pinned ClamAV image and FreshClam client. It verifies database loading, rejects definitions older than 48 hours, accepts a harmless synthetic PDF and rejects the standard harmless antivirus test pattern. It publishes only `main.cvd`, `daily.cvd`, `bytecode.cvd` and `acceptance.json`. Upstream CVDs and their embedded signatures are unchanged. Upstream ownership and terms continue to apply; this mirror does not relicense them.

The scheduled job checks every six hours and caches definitions and FreshClam state, including cooldowns. It does not rotate clients or remove cooldown state after a denial. A failed update publishes nothing; the previous successful release remains. Consumer freshness and signature checks remain mandatory. Releases are retained; existing assets are not overwritten.

The only publication credential is the repository's built-in, short-lived `GITHUB_TOKEN`. No application secret or newly provisioned key is used. No file from the private application repository is checked out here. Server-side scanning stays local and private; customer uploads are never submitted to GitHub.

## Consumer

Use the supported FreshClam private mirror mechanism with this read-only origin:

```
PrivateMirror https://github.com/alivaliandabil-dotcom/eadehyar-clamav-definitions/releases/latest/download
ScriptedUpdates no
TestDatabases yes
```

The delivery must be tested with FreshClam before activation. Do not weaken CVD signature, load testing or freshness checks to make a download succeed.

## Verification and recovery

The same exporter passed an isolated initial fetch/load/clean/pattern test before this publisher was prepared. PR checks exercise current/stale/future/malformed version handling. The first published release and a repeated cached execution must also pass; downstream FreshClam, private daemon and actual document flow acceptance are separate.

Recovery disables the publisher schedule or consumer update task. Previously signed definitions and release history remain available, and consumers fail closed when stale. No application database or storage operation is part of this repository.

References: [ClamAV private mirrors](https://docs.clamav.net/appendix/CvdPrivateMirror.html), [official images](https://github.com/Cisco-Talos/clamav-docker), [FreshClam error/cooldown guidance](https://docs.clamav.net/faq/faq-freshclam).
