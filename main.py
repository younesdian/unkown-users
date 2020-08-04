import subprocess
from datetime import datetime, timedelta
from twilio.rest import Client

try:
    from scapy.all import sniff, Ether, DHCP
except:
    print("Needs Scapy library.")
    print("pip install scapy")
    print("Scapy needs dnet: https://pypi.python.org/pypi/dnet")
    exit()

interface = "en0"
alert_delay = timedelta(hours=2)

#List of macaddress and name of devices
residents = {
    "x0:x0:00:x0:xx:00": "iPhone of XXX"
}


class Device:
    def __init__(self, name="", mac=""):
        self.name = name
        self.mac = mac
        self.last_seen = datetime.fromtimestamp(0)


devices = []


print("Listening on interface {}".format(interface))

while True:
    current_time = datetime.now()
    a = sniff(iface=interface, filter="port 67 or port 68", count=1)
    hostname = "Unknown"
    mac_address = a[Ether][0].src
    for opt in a[0][DHCP].options:
        if isinstance(opt, tuple):
            option, value = opt
            if option == "hostname":
                say_hostname = hostname = value

    device = None
    for dev in devices:
        if dev.mac == mac_address:
            device = dev
    if not device:
        device = Device(name=hostname, mac=mac_address)
        devices.append(device)

    for item in [device.name, device.mac]:
        if item in residents.keys():
            say_hostname = residents[item]

    for keys in residents.keys():
        if not device.mac in keys:
            account_sid = "Twilio account ID"
            auth_token = "Twilio AuthToken"
            msg = "{}: {} ({}) has joined".format(current_time, device.name, device.mac)
            client = Client(account_sid, auth_token)

            message = client.messages.create(
                from_="whatsapp:TWILIO_NUMBER", body=msg, to="whatsapp:YOUR_NUMBER"
            )

            print(message.sid)
            print(msg)

