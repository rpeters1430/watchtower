# Images

## Overview

The `/v1/images/` endpoint lists the images tracked by Watchtower along with their current digests and container counts.
Include `images` in [`http-api-endpoints`](../../../configuration/http-api/index.md#http_api_endpoints) to enable it.
The same endpoint name also enables [`GET /v1/images/usage`](#disk_usage) and [`POST /v1/images/prune`](#removing_unused_images).

## Response Format

The `/v1/images` endpoint returns a JSON object with image statuses:

```json
{
    "images": [
        {
            "name": "nginx:latest",
            "image_id": "sha256:1111...",
            "digest": "sha256:2222...",
            "containers": 3
        }
    ],
    "count": 1,
    "timestamp": "2025-01-20T11:30:45Z",
    "api_version": "v1"
}
```

- `name`: Image name with tag
- `image_id`: Local image config ID (sha256:...)
- `digest`: Registry manifest digest (sha256:...). Empty for locally-built images.
- `containers`: Number of watched containers using this image

## Parameters

### Image Name

The `name` parameter filters results to a specific image by exact name.

```bash
curl -H "Authorization: Bearer mytoken" "localhost:8080/v1/images?name=nginx:latest"
```

### Image ID

The `id` parameter filters results to a specific image by its image ID.

```bash
curl -H "Authorization: Bearer mytoken" "localhost:8080/v1/images?id=sha256:1111..."
```

## HTTP Status Codes

| Status Code | Description                                    |
|:-----------:|:-----------------------------------------------|
|     200     | Images retrieved successfully                  |
|     401     | Invalid or missing authentication token        |
|     500     | Internal server error during request processing|

## Disk Usage

`GET /v1/images/usage` reports how much disk space Docker images take on the host, as `docker system df` does:

```bash
curl -H "Authorization: Bearer mytoken" localhost:8080/v1/images/usage
```

```json
{
    "total_size": 8400000000,
    "reclaimable": 2100000000,
    "total_count": 31,
    "active_count": 18,
    "timestamp": "2025-01-20T11:30:45Z",
    "api_version": "v1"
}
```

- `total_size`: Bytes used by all images. Shared layers are counted once.
- `reclaimable`: Bytes that removing every unused image would free.
- `total_count`: Number of images on the host.
- `active_count`: Number of images at least one container, running or stopped, uses.

## Removing Unused Images

`POST /v1/images/prune` removes images that no container uses, like `docker image prune`:

```bash
# Only dangling (untagged) images, like docker image prune
curl -X POST -H "Authorization: Bearer mytoken" localhost:8080/v1/images/prune

# Every image no container uses, like docker image prune --all
curl -X POST -H "Authorization: Bearer mytoken" "localhost:8080/v1/images/prune?all=true"
```

```json
{
    "all": true,
    "images_deleted": 7,
    "untagged": ["nginx:1.27", "postgres:16"],
    "space_reclaimed": 2100000000,
    "timestamp": "2025-01-20T11:30:45Z",
    "api_version": "v1"
}
```

!!! Warning
    With `all=true` every image no container uses is removed, including images kept for projects that are not running and the image scanner's image. Watchtower downloads the scanner image again before its next scan.

The prune covers every image on the host, not only the ones Watchtower watches. It is refused with `409` while an update runs, so an image that was just pulled is never removed before its container is recreated. The request is given up to five minutes.

| Status Code | Description                                    |
|:-----------:|:-----------------------------------------------|
|     200     | Images removed (the counts can be zero)        |
|     400     | `all` is not `true` or `false`                 |
|     401     | Invalid or missing authentication token        |
|     409     | An update is running                           |
|     500     | The Docker daemon could not remove images      |
