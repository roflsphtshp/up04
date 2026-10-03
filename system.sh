#!/bin/bash
output_file="/opt/system_info"
echo -e "Время запуска | Нагрузка на CPU (%) | Нагрузка на RAM (%) | Свободное место (Гб)" >> "$output_file"
echo "-------------------------------------------------------------------------------" >> "$output_file"
current_time=$(date +"%m.%d %H:%M")
cpu_load=$(top -bn1 | grep 'Cpu(s)' | awk '{print 100-$8}')
ram_load=$(free | grep Mem | awk '{printf "%.2f", $3/$2 * 100.0}')
free_space=$(df -BG / | grep / | awk '{print $4}' | sed 's/G//')
printf "%-13s | %-19s | %-19s | %-20s\n" "$current_time" "$cpu_load" "$ram_load" "$free_space" >> "$output_file"
