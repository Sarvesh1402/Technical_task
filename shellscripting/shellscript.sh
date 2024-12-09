#!/bin/bash 
THRESHOLD=20
EMAIL="kalagatesarvesh14@gmail.com" 
LOG_FILE="/var/log/resource_monitor.log" 
while true; do 
# Get CPU usage 
CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}') 
# Get memory usage 
MEM=$(free | grep Mem | awk '{print $3/$2 * 100.0}') 
# Get disk usage 
DISK=$(df / | grep / | awk '{print $5}' | sed 's/%//') 
# Check thresholds and send alerts 
if (( $(echo "$CPU > $THRESHOLD" | bc -l) )); then 
echo "CPU usage is above $THRESHOLD% ($CPU%)" | mail -s "CPU Alert" $EMAIL 
fi 
if (( $(echo "$MEM > $THRESHOLD" | bc -l) )); then 
echo "Memory usage is above $THRESHOLD% ($MEM%)" | mail -s "Memory Alert" $EMAIL 
fi 
if (( DISK > THRESHOLD )); then 
echo "Disk usage is above $THRESHOLD% ($DISK%)" | mail -s "Disk Alert" $EMAIL 
fi 
sleep 60 
done 
