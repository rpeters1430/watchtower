# Security

## Overview

The `/v1/security` endpoints show what [image scanning](../../../advanced-features/image-scanning/index.md) found in each container's running image, and scan running images on request.
Include `security` in [`http-api-endpoints`](../../../configuration/http-api/index.md#http_api_endpoints) to enable them. The [web UI](../ui/index.md) uses them for its Security page.

Scanning on request works whether or not [`scan`](../../../configuration/image-scanning/index.md#scan) is on. That setting only decides whether pending updates are scanned before they are applied.

| **Method** | **Path**                 | **Purpose**                                                            |
|:----------:|:-------------------------|:-----------------------------------------------------------------------|
|   `GET`    | `/v1/security`           | Scanner setup, scan progress, and each container's latest scan summary |
|   `GET`    | `/v1/security/{name}`    | One container's latest scan with every finding                         |
|   `POST`   | `/v1/security/scan`      | Start scanning running images                                          |

All three need the [API token](../../../configuration/http-api/index.md#http_api_token).

## Where Results Come From

Each container keeps its latest report, which comes from either:

- **An update scan.** With `scan` on, each update cycle scans the new and the running image of every pending update.
  The report covers the running image and includes an `update` object listing what the waiting update fixes and introduces, and whether the [scan gate](../../../configuration/image-scanning/index.md#scan-gate) holds it.
  Once the update is applied, the report covers the new image instead.
- **A scan on request.** `POST /v1/security/scan` scans the image each container runs now, against the latest vulnerability database.
  A waiting update's comparison is kept as long as the container still runs the same image.

Reports are saved to `security.json` in the [data directory](../../../configuration/http-api/index.md#data_directory), so they survive a restart when a volume is mounted there.
A container's report is dropped 30 days after its last scan.

## Overview of All Containers

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/v1/security
```

```json
{
    "available": true,
    "scanner": "trivy",
    "scanner_image": "aquasec/trivy:latest",
    "ignore_unfixed": false,
    "scan_updates": true,
    "gate": "high",
    "saved": true,
    "job": {"running": false, "started_at": "2026-10-14T09:00:00Z", "finished_at": "2026-10-14T09:03:10Z", "total": 5, "done": 5, "failed": 0},
    "containers": [
        {
            "name": "web",
            "image": "nginx:1.25",
            "image_id": "sha256:3b25b682ea82...",
            "scanner": "trivy",
            "scanned_at": "2026-10-14T09:02:41Z",
            "counts": {"critical": 2, "high": 3, "medium": 1, "low": 0, "unknown": 0},
            "fixable": 3,
            "update": {
                "latest_image_id": "sha256:9c7a54a9a43c...",
                "fixed_counts": {"critical": 2, "high": 0, "medium": 0, "low": 0, "unknown": 0},
                "introduced_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
                "held": false,
                "gate": "high"
            }
        }
    ],
    "timestamp": "2026-10-14T09:05:00Z",
    "api_version": "v1"
}
```

| **Field**       | **Description**                                                                                   |
|:----------------|:--------------------------------------------------------------------------------------------------|
| `available`     | `false` when Watchtower could not set up the scanner; `reason` then says why                      |
| `scan_updates`  | Whether pending updates are scanned before they are applied (the `scan` setting)                  |
| `gate`          | The scan gate in force: `off`, `low`, `medium`, `high`, or `critical`                             |
| `job`           | Progress of the latest scan on request. `current` names the containers being scanned               |
| `counts`        | Findings in the running image by severity                                                         |
| `fixable`       | Findings with a published fixed version                                                           |
| `error`         | Why the running image could not be scanned                                                        |
| `update`        | How a waiting update changes the findings, when one is waiting                                    |

The overview leaves out finding lists to stay small.

## One Container's Findings

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/v1/security/web
```

The response has the same report under `container`, plus `findings`, and `update.fixed` and `update.introduced` when an update is waiting:

```json
{
    "id": "CVE-2026-0101",
    "kind": "vulnerability",
    "severity": "critical",
    "package": "openssl",
    "installed_version": "3.0.13-1",
    "fixed_version": "3.0.15-1",
    "title": "OpenSSL: remote code execution in X.509 name checks",
    "url": "https://avd.aquasec.com/nvd/cve-2026-0101"
}
```

`kind` is `vulnerability`, `secret`, or `misconfiguration`. A misconfiguration carries a `resolution` describing the change that fixes it.
Findings are sorted worst first, and at most 1000 are kept per container (`truncated` is then `true`).
A container that has not been scanned returns `404`.

## Scanning on Request

```bash
# Every watched container
curl -X POST -H "Authorization: Bearer <token>" http://localhost:8080/v1/security/scan

# Only some containers
curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
    -d '{"containers": ["web", "db"]}' http://localhost:8080/v1/security/scan
```

The scan runs in the background and the request returns `202 Accepted` with the job. Poll `GET /v1/security` for progress; containers sharing an image share one scan.

| **Status** | **Meaning**                                    |
|:----------:|:-----------------------------------------------|
|   `202`    | The scan started                               |
|   `400`    | The body is not valid JSON                     |
|   `404`    | No watched container matches the names given   |
|   `409`    | A scan is already running                      |
|   `503`    | No scanner is available                        |
