# publish
dotnet publish -c Release -r linux-x64 --self-contained true

ssh optionslab 'systemctl stop gateway'

# Getaway
rsync -vz --delete --recursive --exclude='appsettings.Production.json' Gateway/bin/Release/net*/linux-x64/publish/ optionslab:/opt/gateway/

# CookieGateway
rsync -vz --delete --recursive --exclude='appsettings.Production.json' CookieGateway/bin/Release/net*/linux-x64/publish/ optionslab:/opt/gateway/

# Feed
rsync -vz --delete --recursive --exclude='appsettings.Production.json' Feed/bin/Release/net*/linux-x64/publish/ optionslab:/opt/feed/


ssh optionslab 'systemctl start gateway'
