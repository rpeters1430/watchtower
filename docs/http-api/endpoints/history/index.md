# History

## Overview

The `/v1/history` endpoint returns up to 500 historical scan results. They are saved to `history.json` in the [data directory](../../../configuration/http-api/index.md#data_directory) when one is mounted, and otherwise kept in memory until Watchtower restarts.
Include `history` in [`http-api-endpoints`](../../../configuration/http-api/index.md#http_api_endpoints) to enable this read-only endpoint.

## Parameters

### Since

The `since` parameter filters entries to those at or after the specified RFC3339 timestamp.

```bash
curl -H "Authorization: Bearer mytoken" "localhost:8080/v1/history?since=2025-01-20T11:00:00Z"
```

### Until

The `until` parameter filters entries to those at or before the specified RFC3339 timestamp.

```bash
curl -H "Authorization: Bearer mytoken" "localhost:8080/v1/history?until=2025-01-20T12:00:00Z"
```

### Limit

The `limit` parameter restricts the maximum number of entries returned.

```bash
curl -H "Authorization: Bearer mytoken" "localhost:8080/v1/history?limit=10"
```

### Combining Parameters

Parameters can be combined to query a specific time range with a limit:

```bash
curl -H "Authorization: Bearer mytoken" "localhost:8080/v1/history?since=2025-01-20T11:00:00Z&until=2025-01-20T12:00:00Z&limit=50"
```

## Response Format

The `/v1/history` endpoint returns a JSON object with scan history entries:

```json
{
    "entries": [
        {
            "timestamp": "2025-01-20T11:30:45Z",
            "kind": "scan",
            "scanned": 8,
            "updated": 0,
            "failed": 0,
            "restarted": 0,
            "skipped": 2
        },
        {
            "timestamp": "2025-01-20T12:30:45Z",
            "kind": "scan",
            "scanned": 8,
            "updated": 1,
            "failed": 0,
            "restarted": 0,
            "skipped": 0,
            "containers": [
                {
                    "name": "sonarr",
                    "image": "lscr.io/linuxserver/sonarr:latest",
                    "outcome": "updated",
                    "from_image_id": "sha256:5d1a...",
                    "to_image_id": "sha256:9b7c...",
                    "from_version": "4.0.14",
                    "to_version": "4.0.15"
                }
            ]
        }
    ],
    "count": 2,
    "timestamp": "2025-01-20T12:35:00Z",
    "api_version": "v1"
}
```

Each entry has a `kind`:

- `scan`: an update scan, whether scheduled or started through [`/v1/update`](../update/index.md).
- `check`: an update availability check started through [`/v1/check`](../check/index.md). No containers are changed, so `updated` and `restarted` are `0`. `scanned` is the number of containers checked, `failed` is the number that could not be checked, and `updates_available` is the number with a newer image.

An entry for a scan that ended in an error also has `"scan_failed": true`, and its counts are those the scan reached.
The field is omitted for other scans.

### Containers

`containers` names the containers an entry is about. It lists only containers with something to report, so a scan that changed nothing has no `containers` field. Entries recorded before this field existed don't have it either.

| **Field**                         | **Description**                                                                                     |
|:----------------------------------|:----------------------------------------------------------------------------------------------------|
| `name`                            | Container name                                                                                      |
| `image`                           | Image name with tag                                                                                 |
| `outcome`                         | `updated`, `failed`, `restarted` (because a container it depends on was updated), or `available` (a newer image was found but not applied, by a check or a [monitor-only](../../../configuration/update-behavior/index.md#monitor_only) scan) |
| `from_image_id`, `to_image_id`    | Image IDs before and after the update, or the running and newer image for `available`             |
| `from_version`, `to_version`      | The images' `org.opencontainers.image.version` annotations, when the image sets them              |
| `error`                           | Why the container failed, for `failed`                                                              |

## HTTP Status Codes

| Status Code | Description                                    |
|:-----------:|:-----------------------------------------------|
|     200     | History retrieved successfully                 |
|     400     | Invalid query parameter                        |
|     401     | Invalid or missing authentication token        |
|     500     | Internal server error during request processing|
