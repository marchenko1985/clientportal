# publish
dotnet publish -c Release -r linux-x64 --self-contained true

# gateway
ssh clientportal 'systemctl stop gateway'
rsync -vz --delete --recursive Gateway/bin/Release/net*/linux-x64/publish/ clientportal:/opt/gateway/
ssh clientportal 'systemctl start gateway'
