# ATTACK-Navi Helm Chart

Deploy ATTACK-Navi to a Kubernetes cluster using the included Helm chart.

## Chart Overview

| Field | Value |
|---|---|
| Chart name | `attack-nav` |
| Chart version | `1.0.0` |
| App version | `1.0.0` |
| Type | Application |
| Location | `helm/attack-nav/` |

## Prerequisites

- Kubernetes 1.21+
- Helm 3.x
- `kubectl` configured to your target cluster

## Quick Start

```bash
# From the repo root — install into the 'attack-navi' namespace
helm install attack-navi ./helm/attack-nav   --namespace attack-navi   --create-namespace
```

## Configuration

All configurable values are in `helm/attack-nav/values.yaml`.

### Core Values

| Parameter | Default | Description |
|---|---|---|
| `replicaCount` | `1` | Number of app pod replicas |
| `image.repository` | `ghcr.io/teamstarwolf/attack-nav` | Container image repository |
| `image.tag` | `latest` | Container image tag |
| `image.pullPolicy` | `IfNotPresent` | Kubernetes image pull policy |
| `service.type` | `ClusterIP` | Kubernetes service type |
| `service.port` | `80` | Service port |

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
helm install attack-navi ./helm/attack-nav   --namespace attack-navi   --create-namespace   -f values-prod.yaml
```

### Resources

Default resource requests and limits:

| | CPU | Memory |
|---|---|---|
| Request | `100m` | `64Mi` |
| Limit | `200m` | `128Mi` |

Increase these for heavier use (large ATT&CK datasets, many concurrent users):

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 200m
    memory: 128Mi
```

### Backend Proxy (Optional)

The chart includes an optional backend proxy sidecar for integrating private threat intelligence platforms.

```yaml
proxy:
  enabled: true
  image:
    repository: ghcr.io/teamstarwolf/attack-nav-proxy
    tag: "latest"
  env:
    OPENCTI_URL: "https://opencti.internal"
    OPENCTI_TOKEN: "your-token-here"
    MISP_URL: "https://misp.internal"
    MISP_API_KEY: "your-api-key-here"
```

> **Security note:** Store API keys in a Kubernetes Secret and reference them via `envFrom` rather than embedding values directly. The `env` fields shown above are convenience placeholders.

## Templates

| Template | Description |
|---|---|
| `deployment.yaml` | Main app deployment with optional proxy sidecar |
| `service.yaml` | ClusterIP service exposing port 80 |
| `ingress.yaml` | Optional ingress (disabled by default) |

## Upgrading

```bash
helm upgrade attack-navi ./helm/attack-nav   --namespace attack-navi   --reuse-values   --set image.tag=v0.6.0
```

## Uninstalling

```bash
helm uninstall attack-navi --namespace attack-navi
```

## Building the Container Image

The chart references `ghcr.io/teamstarwolf/attack-nav`. To build and push:

```bash
# Build
docker build -t ghcr.io/teamstarwolf/attack-nav:latest .

# Push (requires GitHub Packages token)
docker push ghcr.io/teamstarwolf/attack-nav:latest
```

> The Docker setup is not yet in CI. Building and pushing the container image is currently a manual step.
> See the open tech-debt item in [ROADMAP.md](../ROADMAP.md).
