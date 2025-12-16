1. Start /challenge/launch
2. Load dos/disk1.img, reboot from menu, and follow the DOS installation instructions
3. Load dos/disk2.img and dos/disk3.img when prompted
4. Eject all floppy disks and hit enter to reboot to c:\
5. Load pcnet/disk1.vfd and run these commands:
```
md \pcnet
copy a:\pktdrvr\pcntpk.com \pcnet\pcntpk.com
```
6. Eject pcnet/disk1.vfd and load mtcp/disk1.img
7. Make the c:\mtcp directory and edit the following into c:\mtcp\mtcp.cfg
```
PACKETINT 0x60
HOSTNAME DOSBOX
IPADDR 192.168.13.100
NETMASK 255.255.255.0
```
8. Run these commands:
```
\pcnet\pcntpk int=0x60 bustype=pci
set mtcpcfg=c:\mtcp\mtcp.cfg
a:\nc -target 192.168.13.37 1337
```
9. Copy the flag to the clipboard
