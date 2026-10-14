<div align="center">
  <img src="./logo.png" width="450" alt="Watchtower logo" />

# Watchtower (rpeters1430 fork)

  Automate Docker container image updates, now with a built-in web UI
  <br/><br/>

  [![Apache-2.0 License](https://img.shields.io/github/license/rpeters1430/watchtower.svg)](./LICENSE.md)
  [![Image](https://img.shields.io/badge/image-ghcr.io%2Frpeters1430%2Fwatchtower-blue)](https://github.com/rpeters1430/watchtower/pkgs/container/watchtower)

</div>

> [!NOTE]
> This is a personal fork of [nicholas-fedor/watchtower](https://github.com/nicholas-fedor/watchtower), which is itself the maintained fork of [containrrr/watchtower](https://github.com/containrrr/watchtower).
> It is not affiliated with or supported by either project. Report problems with this fork in [its issue tracker](https://github.com/rpeters1430/watchtower/issues), not upstream.

## What it does

Watchtower watches your running containers. When a newer image is pushed to Docker Hub or your own registry, it pulls the image, stops the old container gracefully, and starts a new one with the same options it was originally deployed with.

Everything upstream Watchtower can do still works here: schedules, label filtering, monitor-only mode, lifecycle hooks, private registries, Git-driven updates, and notifications through [shoutrrr](https://github.com/nicholas-fedor/shoutrrr).

Watchtower is meant for homelabs, media centers, local development, and similar setups. It is **not** recommended for commercial or production environments; look at Kubernetes with CI/CD for that.

## What this fork adds

The goal of this fork is to make Watchtower easier to use, with a web UI built into the same container.

| Feature | What you get |
| --- | --- |
| **Web UI** | A page at `http://<host>:8080/` that lists watched containers, checks them for newer images, updates the ones you pick, and shows recent scans. Light and dark themes. Served by Watchtower itself: no extra container, and the page loads nothing from other sites. |
| **Settings you can change while running** | Turn monitor-only mode, cleanup of old images, and rolling restarts on or off, and change the update schedule, from the UI or the `/v1/settings` API. No restart needed. |
| **Scan history** | Every scheduled scan, update, and update check is recorded and shown in the UI or at `/v1/history`. |
| **Saved state** | With a volume mounted at `/data`, changed settings and scan history survive restarts. Without it, both are kept in memory and nothing fails. |
| **Single-container updates** | Update one container from the UI without touching the rest. |

The image is published as `ghcr.io/rpeters1430/watchtower:latest` from the `main` branch. Each build is also tagged `sha-<commit>` if you need to pin or roll back to a specific one. Only `linux/amd64` images are built.

## Docker Compose guide

### 1. Create a folder and a token

```console
mkdir -p ~/watchtower && cd ~/watchtower
echo "WATCHTOWER_HTTP_API_TOKEN=$(openssl rand -hex 32)" > .env
echo "WATCHTOWER_HTTP_API_EVENTS_TOKEN=$(openssl rand -hex 32)" >> .env
chmod 600 .env
```

The first token is what you type into the web UI to sign in. Keep the `.env` file private.

### 2. Create `compose.yaml`

```yaml
services:
  watchtower:
    image: ghcr.io/rpeters1430/watchtower:latest
    container_name: watchtower
    restart: unless-stopped
    env_file: .env
    environment:
      # Your time zone, so the schedule runs at the local time you expect.
      TZ: America/New_York

      # Turn on the web UI and the API endpoints it uses.
      WATCHTOWER_HTTP_API_ENDPOINTS: all
      # Keep scheduled updates running while the update endpoint is enabled.
      WATCHTOWER_HTTP_API_PERIODIC_POLLS: "true"

      # When to check for updates: 4:00 every morning.
      # Six fields: second minute hour day-of-month month day-of-week.
      # You can change this later on the UI's Settings page.
      WATCHTOWER_SCHEDULE: "0 0 4 * * *"

      # Remove the old image after a container is updated.
      WATCHTOWER_CLEANUP: "true"

      # Let Watchtower update itself even though it publishes port 8080.
      # Without this, self-updates are skipped while a port is published.
      WATCHTOWER_EPHEMERAL_SELF_UPDATE: "true"

      # Optional: send a notification after each update. See the shoutrrr docs for URL formats.
      # WATCHTOWER_NOTIFICATION_URL: discord://token@channel
    volumes:
      # Lets Watchtower see and recreate your containers.
      - /var/run/docker.sock:/var/run/docker.sock
      # Keeps changed settings and scan history across restarts.
      - ./data:/data
      # Optional: credentials for private registries (created by `docker login`).
      # - ~/.docker/config.json:/config.json:ro
    ports:
      # Web UI and API. Only reachable from this machine; see "Opening the UI to your network".
      - 127.0.0.1:8080:8080
```

### 3. Start it

```console
docker compose up -d
docker compose logs -f watchtower
```

Open <http://localhost:8080/> and sign in with the `WATCHTOWER_HTTP_API_TOKEN` value from `.env`.

### 4. Keep it up to date

With `WATCHTOWER_EPHEMERAL_SELF_UPDATE` set, Watchtower updates itself along with your other containers. It starts a short-lived helper container that replaces the old Watchtower and then removes itself; this mode is marked experimental upstream.

Without it, Watchtower skips its own updates because port 8080 is published (the log says `Published port detected - self-updates disabled.`). The new container could not bind the port while the old one still holds it. In that case, update Watchtower by hand:

```console
docker compose pull && docker compose up -d
```

### Opening the UI to your network

The sample binds the UI to `127.0.0.1`, so only the Docker host can reach it. To use it from other machines on your network, change the port line to `- 8080:8080`, ideally behind a reverse proxy (Caddy, Traefik, Nginx) that adds HTTPS. Without HTTPS, your token and the sign-in cookie cross the network in plain text.

**Never expose the UI or API directly to the Internet.** Anyone who signs in can update containers and change the schedule.

### Common changes

| To... | Set |
| --- | --- |
| See available updates without applying them | `WATCHTOWER_MONITOR_ONLY: "true"` (or toggle it in the UI) |
| Only watch containers you opt in | `WATCHTOWER_LABEL_ENABLE: "true"`, then add the label `com.centurylinklabs.watchtower.enable=true` to those containers |
| Never update a particular container | Add the label `com.centurylinklabs.watchtower.enable=false` to it |
| Check on an interval instead of a schedule | Replace `WATCHTOWER_SCHEDULE` with `WATCHTOWER_POLL_INTERVAL: "86400"` (seconds) |
| Make the UI read-only | Replace `all` with `health,containers,check,history,config`. This leaves out `update` and `settings`, so nobody can update containers or change settings from the page |
| Use the UI without the API changing your schedule | Keep `WATCHTOWER_HTTP_API_PERIODIC_POLLS: "true"` whenever `update` (or `all`) is enabled. Without it, scheduled updates stop and only the UI or API triggers them |

### Which endpoints the UI needs

`all` is the simplest choice. To enable only what you use, list the names in `WATCHTOWER_HTTP_API_ENDPOINTS` (comma separated). Parts of the page whose endpoint is off are hidden or explained.

| Part of the page | Endpoint |
| --- | --- |
| The page itself | `ui` |
| Container list | `containers` |
| Check for updates | `check` |
| Update a container | `update` |
| Scan history | `history` |
| Settings (view) | `config` |
| Settings (change) | `settings` |

## Requirements

- Docker with API version 1.43 or newer (check with `docker version`). Watchtower negotiates the API version automatically.
- A Linux `amd64` host for the published image. For other architectures, build the image yourself with `docker build -f build/docker/Dockerfile.self-local -t watchtower .`.

## Documentation

- Fork-specific features: [Web UI](./docs/http-api/endpoints/ui/index.md), [Settings API](./docs/http-api/endpoints/settings/index.md), [History API](./docs/http-api/endpoints/history/index.md), [HTTP API configuration](./docs/configuration/http-api/index.md).
- Everything else (all configuration options, notifications, labels, private registries) works as in upstream, documented at <https://watchtower.nickfedor.com/>. That site describes upstream's image (`nickfedor/watchtower`); use `ghcr.io/rpeters1430/watchtower:latest` in its examples to run this fork.

## License and attribution

Watchtower is licensed under the [Apache License, Version 2.0](./LICENSE.md). This fork is distributed under the same license.

- Original work: Copyright 2015 Watchtower contributors ([containrrr/watchtower](https://github.com/containrrr/watchtower)), maintained by Nicholas Fedor and contributors at [nicholas-fedor/watchtower](https://github.com/nicholas-fedor/watchtower).
- This fork modifies the original. The changes are the built-in web UI, the runtime settings, history and data directory features, and the container image publishing setup. The [commit history](https://github.com/rpeters1430/watchtower/commits/main) records every change, and [NOTICE](./NOTICE) summarises them.
- Parts of Watchtower contain code under a BSD license from The Go Authors; see [LICENSE.md](./LICENSE.md).
- The web UI embeds the Barlow typeface (Copyright 2017 The Barlow Project Authors), licensed under the SIL Open Font License 1.1; see [OFL.txt](./internal/api/handlers/ui/static/fonts/OFL.txt).

The software is provided "as is", without warranties or conditions of any kind. See the license for details.

## Upstream contributors

Watchtower exists thanks to the people who built and maintain it upstream.

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/en/reference/emoji-key/)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/nicholas-fedor"><img src="https://avatars2.githubusercontent.com/u/71477161?v=4?s=100" width="100px;" alt="Nicholas Fedor"/><br /><sub><b>Nicholas Fedor</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=nicholas-fedor" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=nicholas-fedor" title="Documentation">📖</a> <a href="#maintenance-nicholas-fedor" title="Maintenance">🚧</a> <a href="https://github.com/nicholas-fedor/watchtower/pulls?q=is%3Apr+reviewed-by%3Anicholas-fedor" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://ko-fi.com/foxite"><img src="https://avatars.githubusercontent.com/u/20421657?v=4?s=100" width="100px;" alt="Dirk Kok"/><br /><sub><b>Dirk Kok</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=Foxite" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://piksel.se"><img src="https://avatars2.githubusercontent.com/u/807383?v=4?s=100" width="100px;" alt="nils måsén"/><br /><sub><b>nils måsén</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=piksel" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=piksel" title="Documentation">📖</a> <a href="#maintenance-piksel" title="Maintenance">🚧</a> <a href="https://github.com/nicholas-fedor/watchtower/pulls?q=is%3Apr+reviewed-by%3Apiksel" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://simme.dev"><img src="https://avatars0.githubusercontent.com/u/1596025?v=4?s=100" width="100px;" alt="Simon Aronsson"/><br /><sub><b>Simon Aronsson</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=simskij" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=simskij" title="Documentation">📖</a> <a href="#maintenance-simskij" title="Maintenance">🚧</a> <a href="https://github.com/nicholas-fedor/watchtower/pulls?q=is%3Apr+reviewed-by%3Asimskij" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://codelica.com"><img src="https://avatars3.githubusercontent.com/u/386101?v=4?s=100" width="100px;" alt="James"/><br /><sub><b>James</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=Codelica" title="Tests">⚠️</a> <a href="#ideas-Codelica" title="Ideas, Planning, & Feedback">🤔</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://kopfkrieg.org"><img src="https://avatars2.githubusercontent.com/u/5047813?v=4?s=100" width="100px;" alt="Florian"/><br /><sub><b>Florian</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/pulls?q=is%3Apr+reviewed-by%3AKopfKrieg" title="Reviewed Pull Requests">👀</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=KopfKrieg" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/bdehamer"><img src="https://avatars1.githubusercontent.com/u/398027?v=4?s=100" width="100px;" alt="Brian DeHamer"/><br /><sub><b>Brian DeHamer</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=bdehamer" title="Code">💻</a> <a href="#maintenance-bdehamer" title="Maintenance">🚧</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/rosscado"><img src="https://avatars1.githubusercontent.com/u/16578183?v=4?s=100" width="100px;" alt="Ross Cadogan"/><br /><sub><b>Ross Cadogan</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=rosscado" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/stffabi"><img src="https://avatars0.githubusercontent.com/u/9464631?v=4?s=100" width="100px;" alt="stffabi"/><br /><sub><b>stffabi</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=stffabi" title="Code">💻</a> <a href="#maintenance-stffabi" title="Maintenance">🚧</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ATCUSA"><img src="https://avatars3.githubusercontent.com/u/3581228?v=4?s=100" width="100px;" alt="Austin"/><br /><sub><b>Austin</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=ATCUSA" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://labs.ctl.io"><img src="https://avatars2.githubusercontent.com/u/6181487?v=4?s=100" width="100px;" alt="David Gardner"/><br /><sub><b>David Gardner</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/pulls?q=is%3Apr+reviewed-by%3Adavidgardner11" title="Reviewed Pull Requests">👀</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=davidgardner11" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/dolanor"><img src="https://avatars3.githubusercontent.com/u/928722?v=4?s=100" width="100px;" alt="Tanguy ⧓ Herrmann"/><br /><sub><b>Tanguy ⧓ Herrmann</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=dolanor" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/rdamazio"><img src="https://avatars3.githubusercontent.com/u/997641?v=4?s=100" width="100px;" alt="Rodrigo Damazio Bovendorp"/><br /><sub><b>Rodrigo Damazio Bovendorp</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=rdamazio" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=rdamazio" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://www.taisun.io/"><img src="https://avatars3.githubusercontent.com/u/1852688?v=4?s=100" width="100px;" alt="Ryan Kuba"/><br /><sub><b>Ryan Kuba</b></sub></a><br /><a href="#infra-thelamer" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/cnrmck"><img src="https://avatars2.githubusercontent.com/u/22061955?v=4?s=100" width="100px;" alt="cnrmck"/><br /><sub><b>cnrmck</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=cnrmck" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://harrywalter.co.uk"><img src="https://avatars3.githubusercontent.com/u/338588?v=4?s=100" width="100px;" alt="Harry Walter"/><br /><sub><b>Harry Walter</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=haswalt" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://projectsperanza.com"><img src="https://avatars3.githubusercontent.com/u/74515?v=4?s=100" width="100px;" alt="Robotex"/><br /><sub><b>Robotex</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=Robotex" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://geraldpape.io"><img src="https://avatars0.githubusercontent.com/u/1494211?v=4?s=100" width="100px;" alt="Gerald Pape"/><br /><sub><b>Gerald Pape</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=ubergesundheit" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/fomk"><img src="https://avatars0.githubusercontent.com/u/17636183?v=4?s=100" width="100px;" alt="fomk"/><br /><sub><b>fomk</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=fomk" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/svengo"><img src="https://avatars3.githubusercontent.com/u/2502366?v=4?s=100" width="100px;" alt="Sven Gottwald"/><br /><sub><b>Sven Gottwald</b></sub></a><br /><a href="#infra-svengo" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://liberapay.com/techknowlogick/"><img src="https://avatars1.githubusercontent.com/u/164197?v=4?s=100" width="100px;" alt="techknowlogick"/><br /><sub><b>techknowlogick</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=techknowlogick" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="http://log.c5t.org/about/"><img src="https://avatars1.githubusercontent.com/u/1449568?v=4?s=100" width="100px;" alt="waja"/><br /><sub><b>waja</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=waja" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://scottalbertson.com"><img src="https://avatars2.githubusercontent.com/u/154463?v=4?s=100" width="100px;" alt="Scott Albertson"/><br /><sub><b>Scott Albertson</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=salbertson" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/huddlesj"><img src="https://avatars1.githubusercontent.com/u/11966535?v=4?s=100" width="100px;" alt="Jason Huddleston"/><br /><sub><b>Jason Huddleston</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=huddlesj" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://npstr.space/"><img src="https://avatars3.githubusercontent.com/u/6048348?v=4?s=100" width="100px;" alt="Napster"/><br /><sub><b>Napster</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=napstr" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/darknode"><img src="https://avatars1.githubusercontent.com/u/809429?v=4?s=100" width="100px;" alt="Maxim"/><br /><sub><b>Maxim</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=darknode" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=darknode" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://schmitt.cat"><img src="https://avatars0.githubusercontent.com/u/17984549?v=4?s=100" width="100px;" alt="Max Schmitt"/><br /><sub><b>Max Schmitt</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=mxschmitt" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/cron410"><img src="https://avatars1.githubusercontent.com/u/3082899?v=4?s=100" width="100px;" alt="cron410"/><br /><sub><b>cron410</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=cron410" title="Documentation">📖</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Cardoso222"><img src="https://avatars3.githubusercontent.com/u/7026517?v=4?s=100" width="100px;" alt="Paulo Henrique"/><br /><sub><b>Paulo Henrique</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=Cardoso222" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://coded.io"><img src="https://avatars0.githubusercontent.com/u/107097?v=4?s=100" width="100px;" alt="Kaleb Elwert"/><br /><sub><b>Kaleb Elwert</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=belak" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/wmbutler"><img src="https://avatars1.githubusercontent.com/u/1254810?v=4?s=100" width="100px;" alt="Bill Butler"/><br /><sub><b>Bill Butler</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=wmbutler" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://www.mariotacke.io"><img src="https://avatars2.githubusercontent.com/u/4942019?v=4?s=100" width="100px;" alt="Mario Tacke"/><br /><sub><b>Mario Tacke</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=mariotacke" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://markwoodbridge.com"><img src="https://avatars2.githubusercontent.com/u/1101318?v=4?s=100" width="100px;" alt="Mark Woodbridge"/><br /><sub><b>Mark Woodbridge</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=mrw34" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Ansem93"><img src="https://avatars3.githubusercontent.com/u/6626218?v=4?s=100" width="100px;" alt="Ansem93"/><br /><sub><b>Ansem93</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=Ansem93" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/lukapeschke"><img src="https://avatars1.githubusercontent.com/u/17085536?v=4?s=100" width="100px;" alt="Luka Peschke"/><br /><sub><b>Luka Peschke</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=lukapeschke" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=lukapeschke" title="Documentation">📖</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/zoispag"><img src="https://avatars0.githubusercontent.com/u/21138205?v=4?s=100" width="100px;" alt="Zois Pagoulatos"/><br /><sub><b>Zois Pagoulatos</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=zoispag" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/pulls?q=is%3Apr+reviewed-by%3Azoispag" title="Reviewed Pull Requests">👀</a> <a href="#maintenance-zoispag" title="Maintenance">🚧</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://alexandre.menif.name"><img src="https://avatars0.githubusercontent.com/u/16152103?v=4?s=100" width="100px;" alt="Alexandre Menif"/><br /><sub><b>Alexandre Menif</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=alexandremenif" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/chugunov"><img src="https://avatars1.githubusercontent.com/u/4140479?v=4?s=100" width="100px;" alt="Andrey"/><br /><sub><b>Andrey</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=chugunov" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://noplanman.ch"><img src="https://avatars3.githubusercontent.com/u/9423417?v=4?s=100" width="100px;" alt="Armando Lüscher"/><br /><sub><b>Armando Lüscher</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=noplanman" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/rjbudke"><img src="https://avatars2.githubusercontent.com/u/273485?v=4?s=100" width="100px;" alt="Ryan Budke"/><br /><sub><b>Ryan Budke</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=rjbudke" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://kaloyan.raev.name"><img src="https://avatars2.githubusercontent.com/u/468091?v=4?s=100" width="100px;" alt="Kaloyan Raev"/><br /><sub><b>Kaloyan Raev</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=kaloyan-raev" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=kaloyan-raev" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/sixth"><img src="https://avatars3.githubusercontent.com/u/11591445?v=4?s=100" width="100px;" alt="sixth"/><br /><sub><b>sixth</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=sixth" title="Documentation">📖</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://foosel.net"><img src="https://avatars0.githubusercontent.com/u/83657?v=4?s=100" width="100px;" alt="Gina Häußge"/><br /><sub><b>Gina Häußge</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=foosel" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/8ear"><img src="https://avatars0.githubusercontent.com/u/10329648?v=4?s=100" width="100px;" alt="Max H."/><br /><sub><b>Max H.</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=8ear" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://pjknkda.github.io"><img src="https://avatars0.githubusercontent.com/u/4986524?v=4?s=100" width="100px;" alt="Jungkook Park"/><br /><sub><b>Jungkook Park</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=pjknkda" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://achfrag.net"><img src="https://avatars1.githubusercontent.com/u/5753622?v=4?s=100" width="100px;" alt="Jan Kristof Nidzwetzki"/><br /><sub><b>Jan Kristof Nidzwetzki</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=jnidzwetzki" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://www.lukaselsner.de"><img src="https://avatars0.githubusercontent.com/u/1413542?v=4?s=100" width="100px;" alt="lukas"/><br /><sub><b>lukas</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=mindrunner" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://codingcoffee.dev"><img src="https://avatars3.githubusercontent.com/u/13611153?v=4?s=100" width="100px;" alt="Ameya Shenoy"/><br /><sub><b>Ameya Shenoy</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=codingCoffee" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/raymondelooff"><img src="https://avatars0.githubusercontent.com/u/9716806?v=4?s=100" width="100px;" alt="Raymon de Looff"/><br /><sub><b>Raymon de Looff</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=raymondelooff" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="http://codemonkeylabs.com"><img src="https://avatars2.githubusercontent.com/u/704034?v=4?s=100" width="100px;" alt="John Clayton"/><br /><sub><b>John Clayton</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=jsclayton" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Germs2004"><img src="https://avatars2.githubusercontent.com/u/5519340?v=4?s=100" width="100px;" alt="Germs2004"/><br /><sub><b>Germs2004</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=Germs2004" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/lukwil"><img src="https://avatars1.githubusercontent.com/u/30203234?v=4?s=100" width="100px;" alt="Lukas Willburger"/><br /><sub><b>Lukas Willburger</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=lukwil" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/auanasgheps"><img src="https://avatars2.githubusercontent.com/u/20586878?v=4?s=100" width="100px;" alt="Oliver Cervera"/><br /><sub><b>Oliver Cervera</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=auanasgheps" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/victorcmoura"><img src="https://avatars1.githubusercontent.com/u/26290053?v=4?s=100" width="100px;" alt="Victor Moura"/><br /><sub><b>Victor Moura</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=victorcmoura" title="Tests">⚠️</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=victorcmoura" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=victorcmoura" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mbrandau"><img src="https://avatars3.githubusercontent.com/u/12972798?v=4?s=100" width="100px;" alt="Maximilian Brandau"/><br /><sub><b>Maximilian Brandau</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=mbrandau" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=mbrandau" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/aneisch"><img src="https://avatars1.githubusercontent.com/u/6991461?v=4?s=100" width="100px;" alt="Andrew"/><br /><sub><b>Andrew</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=aneisch" title="Documentation">📖</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/sixcorners"><img src="https://avatars0.githubusercontent.com/u/585501?v=4?s=100" width="100px;" alt="sixcorners"/><br /><sub><b>sixcorners</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=sixcorners" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://arnested.dk"><img src="https://avatars2.githubusercontent.com/u/190005?v=4?s=100" width="100px;" alt="Arne Jørgensen"/><br /><sub><b>Arne Jørgensen</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=arnested" title="Tests">⚠️</a> <a href="https://github.com/nicholas-fedor/watchtower/pulls?q=is%3Apr+reviewed-by%3Aarnested" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/patski123"><img src="https://avatars1.githubusercontent.com/u/19295295?v=4?s=100" width="100px;" alt="PatSki123"/><br /><sub><b>PatSki123</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=patski123" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://rubyroidlabs.com/"><img src="https://avatars2.githubusercontent.com/u/624999?v=4?s=100" width="100px;" alt="Valentine Zavadsky"/><br /><sub><b>Valentine Zavadsky</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=Saicheg" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=Saicheg" title="Documentation">📖</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=Saicheg" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/bopoh24"><img src="https://avatars2.githubusercontent.com/u/4086631?v=4?s=100" width="100px;" alt="Alexander Voronin"/><br /><sub><b>Alexander Voronin</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=bopoh24" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/issues?q=author%3Abopoh24" title="Bug reports">🐛</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://www.teqneers.de"><img src="https://avatars0.githubusercontent.com/u/788989?v=4?s=100" width="100px;" alt="Oliver Mueller"/><br /><sub><b>Oliver Mueller</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=ogmueller" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/tammert"><img src="https://avatars0.githubusercontent.com/u/8885250?v=4?s=100" width="100px;" alt="Sebastiaan Tammer"/><br /><sub><b>Sebastiaan Tammer</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=tammert" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Miosame"><img src="https://avatars1.githubusercontent.com/u/8201077?v=4?s=100" width="100px;" alt="miosame"/><br /><sub><b>miosame</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=miosame" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://mtz.gr"><img src="https://avatars3.githubusercontent.com/u/590246?v=4?s=100" width="100px;" alt="Andrew Metzger"/><br /><sub><b>Andrew Metzger</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/issues?q=author%3Aandrewjmetzger" title="Bug reports">🐛</a> <a href="#example-andrewjmetzger" title="Examples">💡</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/pgrimaud"><img src="https://avatars1.githubusercontent.com/u/1866496?v=4?s=100" width="100px;" alt="Pierre Grimaud"/><br /><sub><b>Pierre Grimaud</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=pgrimaud" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mattdoran"><img src="https://avatars0.githubusercontent.com/u/577779?v=4?s=100" width="100px;" alt="Matt Doran"/><br /><sub><b>Matt Doran</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=mattdoran" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/MihailITPlace"><img src="https://avatars2.githubusercontent.com/u/28401551?v=4?s=100" width="100px;" alt="MihailITPlace"/><br /><sub><b>MihailITPlace</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=MihailITPlace" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/bugficks"><img src="https://avatars1.githubusercontent.com/u/2992895?v=4?s=100" width="100px;" alt="bugficks"/><br /><sub><b>bugficks</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=bugficks" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=bugficks" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/MichaelSp"><img src="https://avatars0.githubusercontent.com/u/448282?v=4?s=100" width="100px;" alt="Michael"/><br /><sub><b>Michael</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=MichaelSp" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/jokay"><img src="https://avatars0.githubusercontent.com/u/18613935?v=4?s=100" width="100px;" alt="D. Domig"/><br /><sub><b>D. Domig</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=jokay" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://maxwells-daemon.io"><img src="https://avatars1.githubusercontent.com/u/260084?v=4?s=100" width="100px;" alt="Ben Osheroff"/><br /><sub><b>Ben Osheroff</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=osheroff" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/dhet"><img src="https://avatars3.githubusercontent.com/u/2668621?v=4?s=100" width="100px;" alt="David H."/><br /><sub><b>David H.</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=dhet" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://www.gridgeo.com"><img src="https://avatars1.githubusercontent.com/u/671887?v=4?s=100" width="100px;" alt="Chander Ganesan"/><br /><sub><b>Chander Ganesan</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=chander" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/yrien30"><img src="https://avatars1.githubusercontent.com/u/26816162?v=4?s=100" width="100px;" alt="yrien30"/><br /><sub><b>yrien30</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=yrien30" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ksurl"><img src="https://avatars1.githubusercontent.com/u/1371562?v=4?s=100" width="100px;" alt="ksurl"/><br /><sub><b>ksurl</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=ksurl" title="Documentation">📖</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=ksurl" title="Code">💻</a> <a href="#infra-ksurl" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/rg9400"><img src="https://avatars2.githubusercontent.com/u/39887349?v=4?s=100" width="100px;" alt="rg9400"/><br /><sub><b>rg9400</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=rg9400" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/tkalus"><img src="https://avatars2.githubusercontent.com/u/287181?v=4?s=100" width="100px;" alt="Turtle Kalus"/><br /><sub><b>Turtle Kalus</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=tkalus" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/SrihariThalla"><img src="https://avatars1.githubusercontent.com/u/7479937?v=4?s=100" width="100px;" alt="Srihari Thalla"/><br /><sub><b>Srihari Thalla</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=SrihariThalla" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://nymous.io"><img src="https://avatars1.githubusercontent.com/u/4216559?v=4?s=100" width="100px;" alt="Thomas Gaudin"/><br /><sub><b>Thomas Gaudin</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=nymous" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://indigo.re/"><img src="https://avatars.githubusercontent.com/u/2804645?v=4?s=100" width="100px;" alt="hydrargyrum"/><br /><sub><b>hydrargyrum</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=hydrargyrum" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://reinout.vanrees.org"><img src="https://avatars.githubusercontent.com/u/121433?v=4?s=100" width="100px;" alt="Reinout van Rees"/><br /><sub><b>Reinout van Rees</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=reinout" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/DasSkelett"><img src="https://avatars.githubusercontent.com/u/28812678?v=4?s=100" width="100px;" alt="DasSkelett"/><br /><sub><b>DasSkelett</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=DasSkelett" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/zenjabba"><img src="https://avatars.githubusercontent.com/u/679864?v=4?s=100" width="100px;" alt="zenjabba"/><br /><sub><b>zenjabba</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=zenjabba" title="Documentation">📖</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://quan.io"><img src="https://avatars.githubusercontent.com/u/3526705?v=4?s=100" width="100px;" alt="Dan Quan"/><br /><sub><b>Dan Quan</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=djquan" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/modem7"><img src="https://avatars.githubusercontent.com/u/4349962?v=4?s=100" width="100px;" alt="modem7"/><br /><sub><b>modem7</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=modem7" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/hypnoglow"><img src="https://avatars.githubusercontent.com/u/4853075?v=4?s=100" width="100px;" alt="Igor Zibarev"/><br /><sub><b>Igor Zibarev</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=hypnoglow" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/patricegautier"><img src="https://avatars.githubusercontent.com/u/38435239?v=4?s=100" width="100px;" alt="Patrice"/><br /><sub><b>Patrice</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=patricegautier" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://jamesw.link/me"><img src="https://avatars.githubusercontent.com/u/8067792?v=4?s=100" width="100px;" alt="James White"/><br /><sub><b>James White</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=jamesmacwhite" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/EDIflyer"><img src="https://avatars.githubusercontent.com/u/13610277?v=4?s=100" width="100px;" alt="EDIflyer"/><br /><sub><b>EDIflyer</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=EDIflyer" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/jauderho"><img src="https://avatars.githubusercontent.com/u/13562?v=4?s=100" width="100px;" alt="Jauder Ho"/><br /><sub><b>Jauder Ho</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=jauderho" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/andriibratanin"><img src="https://avatars.githubusercontent.com/u/20169213?v=4?s=100" width="100px;" alt="Andrii Bratanin"/><br /><sub><b>Andrii Bratanin</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=andriibratanin" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://tamal.vercel.app/"><img src="https://avatars.githubusercontent.com/u/72851613?v=4?s=100" width="100px;" alt="Tamal Das "/><br /><sub><b>Tamal Das </b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=IAmTamal" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/testwill"><img src="https://avatars.githubusercontent.com/u/8717479?v=4?s=100" width="100px;" alt="guangwu"/><br /><sub><b>guangwu</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=testwill" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://hub.lol"><img src="https://avatars.githubusercontent.com/u/48992448?v=4?s=100" width="100px;" alt="Florian Hübner"/><br /><sub><b>Florian Hübner</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=nothub" title="Documentation">📖</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=nothub" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/yubiuser"><img src="https://avatars.githubusercontent.com/u/26622301?v=4?s=100" width="100px;" alt="yubiuser"/><br /><sub><b>yubiuser</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=yubiuser" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/RoboMagus"><img src="https://avatars.githubusercontent.com/u/68224306?v=4?s=100" width="100px;" alt="RoboMagus"/><br /><sub><b>RoboMagus</b></sub></a><br /><a href="#infra-RoboMagus" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/AzariasB"><img src="https://avatars.githubusercontent.com/u/10064282?v=4?s=100" width="100px;" alt="AzariasB"/><br /><sub><b>AzariasB</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=AzariasB" title="Documentation">📖</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ApprenticeofEnder"><img src="https://avatars.githubusercontent.com/u/32110856?v=4?s=100" width="100px;" alt="ApprenticeofEnder"/><br /><sub><b>ApprenticeofEnder</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=ApprenticeofEnder" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/skylenet"><img src="https://avatars.githubusercontent.com/u/1500888?v=4?s=100" width="100px;" alt="skylenet"/><br /><sub><b>skylenet</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=skylenet" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/veeceey"><img src="https://avatars.githubusercontent.com/u/34209028?v=4?s=100" width="100px;" alt="Varun Chawla"/><br /><sub><b>Varun Chawla</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=veeceey" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/LJspice"><img src="https://avatars.githubusercontent.com/u/8888722?v=4?s=100" width="100px;" alt="LJspice"/><br /><sub><b>LJspice</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=LJspice" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/barnabasbusa"><img src="https://avatars.githubusercontent.com/u/21987084?v=4?s=100" width="100px;" alt="Barnabas Busa"/><br /><sub><b>Barnabas Busa</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=barnabasbusa" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=barnabasbusa" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Thubo"><img src="https://avatars.githubusercontent.com/u/4083975?v=4?s=100" width="100px;" alt="Matthias Thubauville"/><br /><sub><b>Matthias Thubauville</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=Thubo" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://gauthierpainteaux.fr"><img src="https://avatars.githubusercontent.com/u/32100821?v=4?s=100" width="100px;" alt="Gauthier Painteaux"/><br /><sub><b>Gauthier Painteaux</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=Greite" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=Greite" title="Tests">⚠️</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=Greite" title="Documentation">📖</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/llc1123"><img src="https://avatars.githubusercontent.com/u/5478730?v=4?s=100" width="100px;" alt="粒粒橙"/><br /><sub><b>粒粒橙</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=llc1123" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ncrosty58"><img src="https://avatars.githubusercontent.com/u/96956364?v=4?s=100" width="100px;" alt="ncrosty58"/><br /><sub><b>ncrosty58</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=ncrosty58" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://justinmontgomery.com"><img src="https://avatars.githubusercontent.com/u/1500269?v=4?s=100" width="100px;" alt="Justin Montgomery"/><br /><sub><b>Justin Montgomery</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/issues?q=author%3Ajmooo" title="Bug reports">🐛</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=jmooo" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/shawly"><img src="https://avatars.githubusercontent.com/u/6448794?v=4?s=100" width="100px;" alt="shawly"/><br /><sub><b>shawly</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=shawly" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://notainutilis.fr"><img src="https://avatars.githubusercontent.com/u/9675966?v=4?s=100" width="100px;" alt="Nota Inutilis"/><br /><sub><b>Nota Inutilis</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=NotaInutilis" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://rooty.name"><img src="https://avatars.githubusercontent.com/u/6276644?v=4?s=100" width="100px;" alt="Stan"/><br /><sub><b>Stan</b></sub></a><br /><a href="https://github.com/nicholas-fedor/watchtower/commits?author=rooty0" title="Code">💻</a> <a href="https://github.com/nicholas-fedor/watchtower/commits?author=rooty0" title="Tests">⚠️</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
