# A script to prevent FlipperZero's BLESpam attack on Windows Hosts.
# It works by scanning for nearby BLE devices, counting the received 
# advertisement packets by each MAC. If a device exceeds the given tolerance,
# the bluetooth adapter is disabled, to prevent further issues such as crashes. 

# Author: Nikolaos Fokos
# Version 1.0
# Date: 29-10-2024

# This script is used for experimentation purposes and does not provide an
# efficient solution for preventing such attacks. It can detect only attacks
# without the use of MAC Randomization. 

import asyncio
import datetime
import os
import sys
import threading

# Library for interacting with the Bluetooth adapter
from bleak import BleakScanner

# Definition of maximum allowed packets per 1 seconds. 
ADV_CL_TOLERANCE = 10
# Duration of time window in seconds
TIME_WINDOW = 1
# Delay between scans
SCAN_DELAY = 0.02

# A dictionary to store all discovered devices
devices = {}

# Function to disable the Bluetooth adapter
def disableBluetooth():
      # Execute an external powershell script for disabling hardware
      os.system("powershell -ExecutionPolicy Bypass -File C:\\path\\to\\Bluetooth.ps1 -Bluetoothstatus Off")
      print("Disabled the Bluetooth adapter.")
      # End the program
      sys.exit()
      
def deviceLogger(device, advertising_data):
      # Get basic device identifiers such as name and MAC
      device_name = device.name or "Unknown Device"
      device_address = device.address 
    
      # Get additional information from the advertiment packets
      device_hostname = advertising_data.local_name or "Unknown Hostname"
      device_rssi = advertising_data.rssi
      
      # Print the devices details and available services
      print(f"MAC: {device_address}, Name: {device_name}, Hostname: {device_hostname}, RSSI: {device_rssi}")
      
      # Basic logging logic
      if device_address not in devices:
            # Add the device on the device dictionary if not found
            devices[device_address] = {
                  "device_name": device_name,
                  "device_hostname": device_hostname,
                  "packet_timestamps": [],
                  "received_packets": 0,
                  "device_rssi": device_rssi,
            }
      
      # Fetch the current time to create a new timestamp
      current_time = datetime.datetime.now()
      
      # Add the received packet's timestamp on the devices attributes
      devices[device_address]["packet_timestamps"].append(current_time)
      devices[device_address]["received_packets"] += 1
      
      # Keep packets that are within the same second
      packet_timestamps = devices[device_address]["packet_timestamps"]
      devices[device_address]["packet_timestamps"] = []
      
      # Update the old timestampts with new, that are within 1 second
      for timestamp in packet_timestamps:
            if (current_time - timestamp).total_seconds() < TIME_WINDOW:
                  devices[device_address]["packet_timestamps"].append(timestamp)
                  
      # Update the packet count
      devices[device_address]["received_packets"] = len(devices[device_address]["packet_timestamps"])
                  
# Check the behavior of the devices when the time window ends
def checkBehavior():
      for device_address, device_details in list(devices.items()):
            # If a devices packets, received within 1 second are more that
            # the maximum tolerance, the Bluetooth adapter is disabled
            if device_details["received_packets"] > ADV_CL_TOLERANCE:
                  print(
                        f"[!]: Dangerous behavior detected."
                        f"    MAC:        {device_address}"
                        f"    Name:       {device_details['device_name']}"
                        f"    Hostname:   {device_details['device_hostname']}"
                        f"    Power:      {device_details['device_rssi']}"
                        )
                  
                  # Disable the Bluetooth adapter
                  disableBluetooth()
            
# Asyncronous function, to scan for near BLE devices and perform a behavior scan
async def bleScanner():
      print("Scanning for BLE devices ...")
      # Start a scan and use deviceLogger as callback
      async with BleakScanner(deviceLogger):
            while True:
                  # Delay of each scan
                  await asyncio.sleep(SCAN_DELAY)
                  threading.Thread(target=checkBehavior())          
                  
# Main
async def main():
      await bleScanner()

# Main execution
if __name__ == "__main__":
      asyncio.run(main())
 