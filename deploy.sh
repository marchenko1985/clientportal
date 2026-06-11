# publish
dotnet publish -c Release -r linux-x64 --self-contained true

ssh optionslab 'systemctl stop gateway'

# NOTE: Gateway and CookieGateway both publish an assembly named `gateway` and
# both rsync into /opt/gateway/ — the LAST block wins (currently CookieGateway).
# Comment out the block you don't want deployed.
# appsettings.Production.json is excluded so the server copy is never
# overwritten by a deploy.

# Getaway
rsync -vz --delete --recursive --exclude='appsettings.Production.json' Gateway/bin/Release/net*/linux-x64/publish/ optionslab:/opt/gateway/

# CookieGateway
rsync -vz --delete --recursive --exclude='appsettings.Production.json' CookieGateway/bin/Release/net*/linux-x64/publish/ optionslab:/opt/gateway/

# Feed — files are synced but the service is NOT restarted here (to keep client
# websockets alive when Feed didn't change). After Feed changes run:
#   ssh optionslab 'systemctl restart feed'
rsync -vz --delete --recursive --exclude='appsettings.Production.json' Feed/bin/Release/net*/linux-x64/publish/ optionslab:/opt/feed/


ssh optionslab 'systemctl start gateway'
