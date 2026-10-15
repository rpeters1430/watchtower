# Image Scanning

Watchtower scans images with [Trivy](https://trivy.dev) to show which known vulnerabilities each container's image has, which ones a waiting update fixes, and what to do about the rest.
With `--scan` turned on, it also scans each update before applying it, and can hold back updates that make things worse.
Configuration options are listed under [Image Scanning](../../configuration/image-scanning/index.md).

## Seeing and Fixing Findings

Enable the [`security`](../../http-api/endpoints/security/index.md) HTTP API endpoint, alongside `ui`, to get a **Security** page in the [web UI](../../http-api/endpoints/ui/index.md):

- A sentence at the top says how many containers have critical or high vulnerabilities, and how many a waiting update would fix.
- **Scan all containers** scans every running image against the latest vulnerability database. It only reads images and changes nothing.
- Each container lists its findings worst first, with the affected package, the installed version, and the version that fixes it.
- **How to fix** sorts the findings by what you can do about them:
    - fixed by a waiting update, with a button to apply it,
    - fixed in a newer package that the image doesn't include yet, which needs a rebuilt image from its maintainer (or from you, if you build it),
    - not fixed anywhere yet, which waits on the package's own project,
    - secrets stored in the image, which should be rotated and passed in at run time,
    - risky image settings, such as running as root, each with its fix.
- The Containers page marks images with critical or high findings, and the Settings page switches update scanning and the scan gate without a restart.

Without the `security` endpoint, scanning still works as described below; results then only appear in logs and notifications.

## How It Works

1. Watchtower checks containers for updates and pulls new images as usual.
2. For each container that will update, Watchtower scans the new image and the running image.
   It runs Trivy in a short-lived container on the same Docker daemon, with the Docker socket mounted so Trivy reads the local images.
3. Watchtower compares the two scans: findings the new image no longer has are **fixed**, findings only the new image has are **introduced**.
4. With a [scan gate](../../configuration/image-scanning/index.md#scan-gate) set, an update whose new image introduces findings at or above the gate is held.
   The container keeps running and is reported as skipped with the findings that held it.
5. After the update, notifications list the vulnerabilities it fixed, for example:

    ```text
    Updated web fixed 2 known vulnerabilities: CVE-2024-0001 (critical), CVE-2024-0003 (high)
    ```

Results are cached by image ID for 12 hours, so an image is not rescanned every cycle while its update waits, but still picks up advisories published since. Scans started from the Security page always use the latest database.

## Requirements

- Watchtower must be able to create containers on the Docker daemon, which it already does to update them.
- The first scan downloads Trivy's vulnerability database (a few hundred MB) into the `watchtower-trivy-cache` volume.
- Scanner containers are labelled `com.centurylinklabs.watchtower.enable=false` and `com.centurylinklabs.watchtower.scanner=true`, so Watchtower never tries to update them. They are removed after each scan.

## Example

```yaml
services:
  watchtower:
    image: ghcr.io/rpeters1430/watchtower:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      WATCHTOWER_SCAN: "true"
      WATCHTOWER_SCAN_GATE: critical
```

## Failure Handling

Scanning never blocks an update on its own. If the scanner image cannot be pulled, a scan times out, or Trivy fails, Watchtower logs a warning and updates without a security review.
Only the opt-in scan gate can hold an update, and only when a scan succeeded.
If the running image cannot be scanned, every finding of the new image counts as introduced, which errs on the side of holding when a gate is set.

## Limitations

- Trivy is the only scanner so far.
- Only images are scanned. Watchtower reports what to fix but does not rebuild images itself.
- Containers built from a Git source are not scanned during updates, because their new image does not exist until it is built.
- Scanning needs the Docker socket on the host. A remote daemon or socket proxy without a local socket is not supported yet.
