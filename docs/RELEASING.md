# Releasing

A release is a milestone: `0.2 Passkeys` becomes version `0.2.0`, in clavia and
[clavia-dashboard](https://github.com/clavia-auth/clavia-dashboard) at the same number.
Clavia follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0.0 a minor
version may change the Management API or a setting, and the changelog says so.

What a release publishes:

| What | Where | Made by |
|---|---|---|
| A git tag `vX.Y.Z` | the repository | the maintainer |
| The container image | `ghcr.io/clavia-auth/clavia:X.Y.Z` (also `X.Y` and `latest`) | the **Release** workflow |
| The GitHub release, with the changelog section as its notes | GitHub | the **Release** workflow |
| The Management API reference, `/vX.Y.Z/` and the site's root | GitHub Pages (`gh-pages`) | the **Docs** workflow, once **Release** succeeded |
| The dashboard's tag | clavia-dashboard | the maintainer |

Claude prepares the release pull request (the **ticket-release** skill); tagging and publishing
are public and hard to take back, so they are the maintainer's.

## 1. Check the milestone

Every issue of the milestone is closed in both repositories, or moved to the next one by
agreement: unfinished work is never released half-done.

```bash
for r in clavia clavia-dashboard; do
  gh api "repos/clavia-auth/$r/milestones?state=open" --jq '.[] | "\(.number) \(.title) open=\(.open_issues)"'
done
```

## 2. Open the release pull request

Branch `chore/release-X.Y.Z`, pull request `Release X.Y.Z`, with `Part of` the release issue.
It changes three things:

- **`CHANGELOG.md`**: a section `## [X.Y.Z] - YYYY-MM-DD` under `## [Unreleased]`, in
  [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) form (Added, Changed, Fixed, Security),
  written for the people who run Clavia, not as a list of commits. Settings, migrations and any
  step an operator must take on upgrading get their own lines. Add the section's link at the foot
  (`[X.Y.Z]: https://github.com/clavia-auth/clavia/releases/tag/vX.Y.Z`) and move `[Unreleased]`
  to compare against it. **This section is the release notes**, word for word.
- **`composer.json`**: `"version": "X.Y.Z"`. A version field changes Composer's lock hash, so
  refresh it without touching a package: `composer update --lock` (never `composer update` of
  `php-db/*`, which is pinned), and keep only the `content-hash` line of the lock file's diff.
- **The same version everywhere a release is named**: `src/Configuration/Version.php` (what
  `/healthz` and the console report), the chart's `version` and `appVersion`
  (`deploy/helm/clavia/Chart.yaml`), and the Compose kit's defaults (`CLAVIA_VERSION` and
  `CLAVIA_DASHBOARD_VERSION` in `deploy/compose/compose.yaml` and `env.example`).
  `DeploymentKitTest` fails until they all agree with `composer.json`.

Merge it once `composer check` is green.

## 3. Tag

Wait for the CI run on the merge commit to finish: the Release workflow refuses a commit whose
checks have not succeeded.

```bash
git fetch origin main
git tag -a vX.Y.Z -m "X.Y.Z" origin/main
git push origin vX.Y.Z
```

A tag of the form `vX.Y.Z-rc.1` publishes a **pre-release**: the image is tagged `X.Y.Z-rc.1` only,
and `latest` and `X.Y` do not move.

## 4. What the Release workflow does

`.github/workflows/release.yml` runs on the tag and stops at the first thing that disagrees:

1. **Verify.** The tagged commit is on `main`; the CI checks succeeded on it; `composer.json`
   declares the tag's version; `CHANGELOG.md` has a section for it.
2. **Image.** Builds the `production` target of `docker/php`, with the repository as the named
   build context `app`, and pushes it to `ghcr.io/clavia-auth/clavia`. The image holds the
   application and its runtime dependencies (`composer install --no-dev`, an authoritative
   classmap, OPcache that does not re-read files); it is PHP-FPM alone, so put Caddy, or any
   FastCGI proxy, in front of it, serving `/app/public`. It does not hold configuration:
   everything comes from `CLAVIA_*` variables.
3. **Release.** Creates the GitHub release for the tag with the changelog section as its notes,
   only after the image exists, so no release is ever without its image.

Build the image yourself the same way:

```bash
docker buildx build docker/php --target production --build-context app=. -t clavia:local
```

## 5. After the workflow

- **Tag the dashboard** at the same version, from its `main`, once its own release pull request is
  merged. The two repositories release together, and the Release workflow cannot do this one.
- **Close the milestone** in both repositories:
  `gh api -X PATCH repos/clavia-auth/clavia/milestones/<number> -f state=closed`
- **Check the published image** pulls and starts:
  `docker run --rm -e CLAVIA_ROOT_DOMAIN=example.test ghcr.io/clavia-auth/clavia:X.Y.Z php bin/clavia config`
- The first time, set the package's visibility on ghcr.io (public, linked to the repository), which
  a workflow cannot do.

## 6. The API reference

`.github/workflows/docs.yml` runs when the Release workflow succeeds on a tag, and publishes the
Management API reference and its guides to GitHub Pages:

- the page is `docs/site/index.html`, Scalar (pinned) over the release's
  `docs/openapi/management-api.yaml`, with a bar naming the release and offering the others. The
  page and its scripts are taken from `main`, the document from the tag, so a fix to the page
  reaches every release published after it, and each release shows its own API;
- the guides are the tag's `docs/guides`, each rendered by `docs/site/guide.html` (marked and
  DOMPurify, pinned) at `/vX.Y.Z/guides/<name>.html`, beside its Markdown, in the order
  `docs/guides/README.md` lists them. The reference's bar and introduction link them. A release
  from before the guides is built without them, and its bar has no Guides link;
- `docs/site/build.sh` builds a release and `docs/site/publish.sh` places it on the `gh-pages`
  branch: `/vX.Y.Z/` for the release, replaced whole if it is published again, and the site's root
  for the newest stable release. A pre-release, or an older release published later, never moves
  the root. `versions.json` lists every release, newest first, for the page's picker;
- nothing is published for a tag the Release workflow refused.

To publish a release by hand (a release made before the workflow existed, or after a fix to the
page): **Actions → Docs → Run workflow**, with the tag (`v0.3.0`). Running it again for a published
release replaces that release's directory, and nothing else.

To preview the page from a branch, with no tag and no workflow:

```bash
docs/site/build.sh dev docs/openapi/management-api.yaml /tmp/clavia-docs "" docs/guides
cd /tmp/clavia-docs && python3 -m http.server 8080   # the page loads its document over HTTP
```

**The first time**, in the repository's settings, **Pages → Build and deployment**: source
*Deploy from a branch*, branch `gh-pages`, folder `/ (root)`. The branch exists once the workflow
has run. The site is then at `https://clavia-auth.github.io/clavia/`.

**A domain of your own** (`docs.example.com`): in the same settings, **Custom domain**, then a
`CNAME` record from that name to `clavia-auth.github.io`, and **Enforce HTTPS** once GitHub has
issued the certificate. GitHub writes the domain into a `CNAME` file on `gh-pages`, which the
workflow never touches.

## If it goes wrong

- **Verify failed**: fix what it names on `main` through a pull request, delete the tag
  (`git push origin :refs/tags/vX.Y.Z`, `git tag -d vX.Y.Z`), and tag the new commit. Nothing was
  published.
- **The image or the release step failed after the image was pushed**: re-run the failed job from
  the Actions tab. A release is created once; if one already exists for the tag, delete it first
  (`gh release delete vX.Y.Z`).
- **The Docs workflow failed**: nothing else depends on it. Fix the cause on `main` and run it by
  hand for the tag (section 6).
- **A published release is wrong**: do not move the tag. Fix forward with a patch release
  (`X.Y.Z+1`) and say so in its changelog.
