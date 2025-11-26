# Netflix N Hack for PS4 (coming soon)

> [!NOTE]
> PS4 version requires very specific circumstances to work. We have a few workaround described below.

## Compatibility 

Before you proceed, please ensure you meet these criteria 

1. Netflix installed on your PS4 below the latest version 
    - If you have existing Jailbreak, you can just install the vulnerable version.
    - this is useful if you can't afford BD-JB or are stuck using PPPwn 
    - if you are on latest firmware, you can downgrade via mitm by downloading from PSN. You cannot jailbreak, however you will be prepared for if a new kernel exploit comes out .

2. Have PS4 Firmware version between 9.00 and 12.02 (for lapse exploit)


## Downgrading Netflix 

Prerequisites:
- Python
- mitmproxy 
- Internet access

```
#install mitmproxy 
pip install mitmproxy 

#start downgrade proxy
mitmproxy -s downgrader.py --ssl-insecure
```
 
Then on your console, go to Netflix press **Options** and **Check for Updates**

It will show that it is downloading latest version, but after installing it should be 1.53

## Exploit

```
mitmproxy -s proxy.py
```

then just simply open Netflix (should take about 30 seconds)

This will spawn Remote JS payload server. Send `payloads/lapse_ps4.js` via netcat or equivalent 

> [!NOTE]
> You will not see any output while exploit is executing. If the app crashes, or PS4 Kernel Panics. Restart console and try again 

This will spawn a bin loader on port 9021

Then you can send your HEN of choice 

If you run into any issues message me on discord!
