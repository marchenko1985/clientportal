# Deployment

In my case i need something simple, no docker, no kubernetes, no fancy CI/CD.

So keeping short note for myself.

## TLDR

```bash
dotnet publish -c Release -r linux-x64 --self-contained true
ssh clientportal 'systemctl stop clientportal'
rsync -avz --delete Web/bin/Release/net10.0/linux-x64/publish/ clientportal:~/clientportal/
ssh clientportal 'systemctl clientportal'
```

## Prerequisites

It is expected that we have an VPS with Ubuntu

And we have configured ssh keys so we can simply

```bash
ssh clientportal
```

Also, it is expected that user has enough privileges to run sudo commands, but all examples will be without it

## Publishing

Thankfully it is possible to publish self contained dotnet app - so we do not need to install anything on target server

```bash
dotnet publish -c Release -r linux-x64 --self-contained true
```

Published build will be here:

```
Web/bin/Release/net10.0/linux-x64/publish/
```

## Deploying

In my case - this is an sample project, so no need to do any fancy CI/CD stuff

What we are going to do is to stop service, rsync fresh build, start service back

```bash
# 1. stop remote service
ssh clientportal 'systemctl stop clientportal'

# 2. rsync our build
rsync -avz --delete Web/bin/Release/net10.0/linux-x64/publish/ clientportal:~/clientportal/

# 3. start service
ssh clientportal 'systemctl clientportal'
```

See [Systemd.md](Systemd.md) to see how to configure service.

## Troubleshooting

If service is not started and you do not want to bother with journalctl just ssh to the verver

Navigate to ~/clientportal

> Do not forget about environment variables, but if you are using `appsettings.Production.json` it will be copied as well

And start app by running

```bash
ASPNETCORE_URLS=http://127.0.0.1:5000 ASPNETCORE_ENVIRONMENT=Production ./Web
```

Also you might want to change log level and formatter to better understand whats going on, or just add `| jq` at the end to have pretty printed json logs
