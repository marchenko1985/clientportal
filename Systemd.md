# Systemd Daemon

Short note for myself

Here is example of configuration file:

[etc/systemd/system/clientportal.service](etc/systemd/system/clientportal.service)

Notes:

- stdout and stderr are by default captured by journalctl, use `journalctl -u clientportal -f` to watch logs
- we are defining production environment here so corresponding appsettings file is used, but we might pass environment variables here as well
- fancy setting to use server gc added
- you must run `systemctl daemon-reload` every time config file is changed
- in my case, app wil not be exposed, otherwise do something like `ASPNETCORE_URLS=http://0.0.0.0:80`

Once we are done

```bash
systemctl daemon-reload
systemctl enable clientportal
systemctl start clientportal
```

To remove it

```bash
systemctl stop clientportal
systemctl disable clientportal
systemctl daemon-reload
```

Stream logs

```bash
journalctl -u clientportal -f
```

Show last

```bash
journalctl -u clientportal -n 100
```
