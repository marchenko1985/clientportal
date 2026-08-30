# publish
dotnet publish -c Release -r linux-x64 --self-contained true

ssh optionslab 'systemctl stop gateway'

# NOTE: Gateway and CookieGateway both publish an assembly named `gateway` and
# both rsync into /opt/gateway/ — the LAST block wins. CookieGateway is the one
# deployed today, so the Gateway block is commented out; swap the comments to
# deploy Gateway instead. (Leaving both live works, but transfers ~110 MB twice.)
# appsettings.Production.json is excluded so the server copy is never
# overwritten by a deploy.
#
# -t preserves modification times, which is what lets rsync's size+mtime quick
# check skip unchanged files outright. Without it the destination mtimes never
# match, so every deploy opens and checksums all ~110 MB of the self-contained
# runtime on both ends — delta transfer still keeps the bytes on the wire small,
# but the work is pointless.

# Gateway
# rsync -vzt --delete --recursive --exclude='appsettings.Production.json' Gateway/bin/Release/net*/linux-x64/publish/ optionslab:/opt/gateway/

# CookieGateway
rsync -vzt --delete --recursive --exclude='appsettings.Production.json' CookieGateway/bin/Release/net*/linux-x64/publish/ optionslab:/opt/gateway/

# Feed — files are synced but the service is NOT restarted here (to keep client
# websockets alive when Feed didn't change). After Feed changes run:
#   ssh optionslab 'systemctl restart feed'
rsync -vzt --delete --recursive --exclude='appsettings.Production.json' Feed/bin/Release/net*/linux-x64/publish/ optionslab:/opt/feed/


ssh optionslab 'systemctl start gateway'
