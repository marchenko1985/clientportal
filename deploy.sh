# publish
dotnet publish -c Release -r linux-x64 --self-contained true

ssh clientportal 'systemctl stop gateway'

# Getaway
rsync -vz --delete --recursive Gateway/bin/Release/net*/linux-x64/publish/ clientportal:/opt/gateway/

# CookieGateway
rsync -vz --delete --recursive CookieGateway/bin/Release/net*/linux-x64/publish/ clientportal:/opt/gateway/

ssh clientportal 'systemctl start gateway'
