# Publication privacy

Keep `.env`, the private identity directory, private keys, database files and
sidecars, pairing exports and backups out of Git and uploaded archives. The
repository ignore rules cover these files. Docker builds use a source allowlist;
the source-package manifest includes the public `.env.example`, not `.env`.
Pairing bundles contain a public certificate and server address: they are not
private keys, but still identify a deployment and should be shared intentionally.

Before opening an existing repository, review all pushed branches/tags, historical
files, and author/committer emails. Removing a file in a new commit does not erase
history. Separately inspect Releases, Actions logs/artifacts, issues/PRs and
attachments. Actions logs and history become public with the repository.
History rewrites, force pushes and deletion of hosted logs need explicit approval.

If a credential was committed, revoke/rotate it first. An automated pattern scan
helps find common credentials, but cannot prove that every file is safe. Do not
upload a ZIP of a development workspace: untracked state may sit outside the
repository and will not be protected by its ignore rules.

References: [GitHub visibility changes](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility),
[removing sensitive history](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
