# Manage NexThink Collector

This script interacts with the NexThink collector, allowing you to start or stop it on a specified device. Also allows for the bulk start and stop on a list of devices.

## How To Use

Start the NexThink collector on a device named "MyDevice":
.\Manage-NexThinkCollector.ps1 -Action "start" -DeviceName "MyDevice"

Stop the NexThink collector on a device named "AnotherDevice":
.\Manage-NexThinkCollector.ps1 -Action "stop" -DeviceName "AnotherDevice"

Stop the NexThink collector on a series of devices:
.\Manage-NexThinkCollector.ps1 -Action "stop" -Import "C:\temp\NexThinkCollector.csv"

## Tags
- NexThink

## Authors

2024-07-09 - **Aaron Whittaker** - Script created as part of the NexThink rollout