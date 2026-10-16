# ATTACK-Navi Helm Chart

Deploy ATTACK-Navi to a Kubernetes cluster using the included Helm chart. The chart deploys the static app (nginx serving the production build) and nothing else.

## Chart Overview

| Field | Value |
|---|---|
| Chart name | `attack-nav` |
| Chart version | `1.1.0` |
| App version | `0.10.0` (tracks `version` in `package.json`; also the default image tag) |
| Type | Application |
| Location | `helm/attack-nav/` |

## Prerequisites

- Kubernetes 1.21+
- Helm 3.x
- `kubectl` configured to your target cluster
- A container registry you can push to

## 1. Build and push the image

No workflow in this repository publishes a container image. `.github/workflows/docker.yml` builds the image and smoke-tests it on pull requests and pushes to `main`, but it never pushes to a registry, so the chart's default `ghcr.io/teamstarwolf/attack-nav` repository holds no image and a bare `helm install` ends in `ImagePullBackOff`. Build the image from the root `Dockerfile` and push it somewhere you control first:

```bash
# From the repo root. Tag with the app version so the chart's default tag matches.
docker build -t registry.example.com/attack-nav:0.10.0 .
docker push registry.example.com/attack-nav:0.10.0
```

The image is built on `nginxinc/nginx-unprivileged`: nginx listens on port 8080 and runs as the unprivileged user 101, which is what the chart's security context expects.

## 2. Install

```bash
# From the repo root - install into the 'attack-navi' namespace
helm install attack-navi ./helm/attack-nav \
  --namespace attack-navi --create-namespace \
  --set image.repository=registry.example.com/attack-nav \
  --set image.tag=0.10.0
```

`image.tag` can be left unset when the tag you pushed equals the chart's `appVersion`.

## Configuration

All configurable values are in `helm/attack-nav/values.yaml`.

### Core Values

| Parameter | Default | Description |
|---|---|---|
| `replicaCount` | `1` | Number of app pod replicas |
| `image.repository` | `ghcr.io/teamstarwolf/attack-nav` | Container image repository. Not published by this repository; override it with your own. |
| `image.tag` | `""` (falls back to `appVersion`, `0.10.0`) | Container image tag. Use an immutable tag; with `pullPolicy: IfNotPresent` a mutable `latest` would never be re-pulled on upgrade. |
| `image.pullPolicy` | `IfNotPresent` | Kubernetes image pull policy |
| `containerPort` | `8080` | Port nginx listens on inside the container (the unprivileged image uses 8080) |
| `service.type` | `ClusterIP` | Kubernetes service type |
| `service.port` | `80` | Service port, forwarded to `containerPort` |
| `podSecurityContext` | `runAsNonRoot: true`, uid/gid `101`, `seccompProfile: RuntimeDefault` | Pod security context |
| `securityContext` | `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]` | Container security context. `/tmp` is an `emptyDir` so nginx can write its pid file and temp buffers. `/etc/nginx/conf.d` is a second `emptyDir` so the image's entrypoint can render the site config and security-header snippet from their templates at start; without it nginx would fall back to the stock config with no security headers, SPA fallback or `/api/` route. |

### Ingress

Ingress is **disabled by default**. Enable it with your cluster's ingress class:

```yaml
# values-prod.yaml
ingress:
  enabled: true
  className: "nginx"
  hosts:
    - host: attack-navi.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: attack-navi-tls
      hosts:
        - attack-navi.example.com
```

```bash
helm install attack-navi ./helm/attack-nav \
  --namespace attack-navi --create-namespace \
  -f values-prod.yaml
```

### Resources

Default resource requests and limits:

| | CPU | Memory |
|---|---|---|
| Request | `100m` | `64Mi` |
| Limit | `200m` | `128Mi` |

Increase these for heavier use (many concurrent users). Example override:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 200m
    memory: 128Mi
```

### Backend proxy

The chart does not deploy the optional credentials proxy in `server/`, and it has no values for OpenCTI or MISP tokens; never put integration secrets in `values.yaml`. To use the proxy with a Kubernetes deployment, run it separately (for example from `server/Dockerfile` with its configuration in a Kubernetes Secret) and enter its URL in the app's Settings > Integrations. `docker-compose.yml` at the repo root runs the app and the proxy together for single-host setups; see [server/README.md](../server/README.md).

The image's `Content-Security-Policy` lives in `nginx-security-headers.conf`, which the Dockerfile installs under `/etc/nginx/templates/` and the nginx entrypoint renders into `/etc/nginx/conf.d` when the container starts. Origins are not added by editing `nginx.conf`: `connect-src` appends whatever the `CSP_EXTRA_CONNECT_SRC` environment variable holds (space-separated origins, empty by default; see [CONFIGURATION.md](CONFIGURATION.md#docker)). A proxy on a different origin than the app, and any OpenCTI, MISP or TAXII server used in direct mode, must be listed there.

The chart cannot pass that variable yet: `values.yaml` has no environment values and `templates/deployment.yaml` gives the container no `env`, so there is nothing for `--set` to reach. The same holds for `PROXY_UPSTREAM` and `NGINX_RESOLVER`, so in a chart deployment the same-origin `/api/` route keeps the image defaults (`http://proxy:8787`, resolved through `127.0.0.11`, Docker's embedded DNS). Until the chart gains a way to set container environment, put the value in the image you push, for example with a two-line Dockerfile on top of the image from step 1:

```dockerfile
FROM registry.example.com/attack-nav:0.10.0
ENV CSP_EXTRA_CONNECT_SRC="https://navi-proxy.example.com"
```

Build and push that under its own tag and point `image.tag` at it. The proxy, in turn, must list the app's origin in its `ALLOWED_ORIGINS` (see [server/README.md](../server/README.md)).

## Templates

| Template | Description |
|---|---|
| `deployment.yaml` | App deployment: one nginx container, non-root security context, probes on the `http` port |
| `service.yaml` | ClusterIP service exposing `service.port`, targeting the container's `http` port |
| `ingress.yaml` | Optional ingress (disabled by default) |

## Upgrading

Push a new image tag, then upgrade to it:

```bash
helm upgrade attack-navi ./helm/attack-nav \
  --namespace attack-navi --reuse-values \
  --set image.tag=<tag-you-pushed>
```

Bump `appVersion` in `Chart.yaml` when `package.json`'s version changes so the default tag stays in step.

## Uninstalling

```bash
helm uninstall attack-navi --namespace attack-navi
```

## Validating the chart

```bash
helm lint ./helm/attack-nav
helm template attack-navi ./helm/attack-nav --set image.tag=0.10.0
```

## CI status

`.github/workflows/docker.yml` builds the image and, running it with the chart's read-only root filesystem (`--read-only` plus tmpfs at `/tmp` and `/etc/nginx/conf.d`), checks that it serves `/`, deep links and the security headers from the rendered config and runs as a non-root user, on pull requests and pushes to `main`. It does not log in to a registry or push the image. Publishing images (and signing them) is a deliberate owner decision that has not been made; until then, building and pushing is the manual step 1 above.
