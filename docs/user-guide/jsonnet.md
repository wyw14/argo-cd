# Jsonnet

Any file matching `*.jsonnet` in a directory app is treated as a Jsonnet file. Argo CD evaluates the Jsonnet and is able to parse a generated object or array.

## Build Environment

Jsonnet apps have access to the [standard build environment](build-environment.md) via substitution into *TLAs* and *external variables*.
It is also possible to add a shared library (e.g. `vendor` folder) relative to the repository root.

E.g. via the CLI:

```bash
argocd app create APPNAME \
  --jsonnet-ext-var-str 'app=${ARGOCD_APP_NAME}' \
  --jsonnet-tla-str 'ns=${ARGOCD_APP_NAMESPACE}' \
  --jsonnet-libs 'vendor'
```

Or by declarative syntax:

```yaml
  directory:
    jsonnet:
      extVars:
        - name: app
          value: $ARGOCD_APP_NAME
      tlas:
        - name: ns
          value: $ARGOCD_APP_NAMESPACE
      libs:
        - vendor
```

## Read-set cache (optional)

> [!NOTE]
> The Jsonnet read-set cache is **opt-in** and disabled by default. Enable it on the repo-server with `--jsonnet-read-set-cache` (or `ARGOCD_REPO_SERVER_JSONNET_READ_SET_CACHE=true`).

When enabled, a directory whose sole manifest is a single, natively evaluated `*.jsonnet` entry can reuse its rendered output across repository revisions. Before reusing a cached render, Argo CD re-verifies on the new, immutable checkout that every file the Jsonnet VM actually read (including files reached through in-repo symlinks) is unchanged, and that every import-search candidate that previously did not exist is still absent. A commit that only touches unrelated files therefore no longer triggers a re-evaluation, while a change to an imported file, the entry itself, a newly added higher-priority same-named library file, or any other semantic input correctly invalidates the cache.

The cache key binds the entry path, resolved external variables and TLAs, library search order, evaluation protocol, project permissions, request options, namespace and repository credential identity. Cached entries contain only relative paths, content digests and the rendered output — never credential or variable plaintext. Renders that exceed the configured read-set, probe-count or total-byte limits (`--jsonnet-read-set-max-files`, `--jsonnet-read-set-max-checks`, `--jsonnet-read-set-max-bytes`) are still served, but are not cached.

> [!WARNING]
> Only native go-jsonnet evaluations with no external I/O are eligible. Config Management Plugins, native callbacks and any source type other than a single native Jsonnet entry never participate, and a cached result is never reused for another namespace, project or repository credential.
