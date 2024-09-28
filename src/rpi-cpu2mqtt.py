# -*- coding: utf-8 -*-
# Python script (runs on 2 and 3) to monitor cpu load, temperature, frequency, free space etc.
# on a Raspberry Pi or Ubuntu computer and publish the data to a MQTT server.
# RUN sudo apt-get install python-pip
# RUN pip install paho-mqtt

#from __future__ import division
import subprocess
import time
import socket
import paho.mqtt.client as paho
import json
import os
import sys
import argparse
import threading
#import update
import config
import re
import html
import uuid

# Imposta le variabili d'ambiente per la lingua
os.environ['LC_ALL'] = 'en_US.UTF-8'
os.environ['LANG'] = 'en_US.UTF-8'


def check_wifi_signal(format):
    try:
        full_cmd =  "ls /sys/class/ieee80211/*/device/net/"
        interface = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE).communicate()[0].strip().decode("utf-8")
        full_cmd = "/sbin/iwconfig {} | grep -i quality".format(interface)
        wifi_signal = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE).communicate()[0]

        if format == 'dbm':
            wifi_signal = wifi_signal.decode("utf-8").strip().split(' ')[4].split('=')[1]
        else:
            wifi_signal = wifi_signal.decode("utf-8").strip().split(' ')[1].split('=')[1].split('/')[0]
            wifi_signal = round((int(wifi_signal) / 70)* 100)

    except Exception:
        wifi_signal = 0

    return wifi_signal


def check_used_space(path):
    st = os.statvfs(path)
    free_space = st.f_bavail * st.f_frsize
    total_space = st.f_blocks * st.f_frsize
    used_space = int(100 - ((free_space / total_space) * 100))

    return used_space


def check_swap():
    full_cmd = "free | grep -i swap | awk 'NR == 1 {if($2 > 0) {print $3/$2*100} else {print 0}}'"
    swap = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE).communicate()[0]
    swap = round(float(swap.decode("utf-8").replace(",", ".")), 1)

    return swap


def check_memory():
    full_cmd = "free | grep -i mem | awk 'NR == 1 {print $3/$2*100}'"
    memory = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE).communicate()[0]
    memory = round(float(memory.decode("utf-8").replace(",", ".")))

    return memory


def check_sys_clock_speed():
    full_cmd = "awk '{printf (\"%.0f\", $1/1000); }' </sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"
    output = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE).communicate()[0]
    return output.decode('utf-8').strip()


def check_uptime(format):
    full_cmd = "awk '{print int($1"+format+")}' /proc/uptime"

    return int(subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE).communicate()[0])


def check_uptime_str():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
    except Exception as e:
        print(f"Errore durante la lettura di /proc/uptime: {e}")
        return None

    giorni = int(uptime_seconds // 86400)
    ore = int((uptime_seconds % 86400) // 3600)
    minuti = int((uptime_seconds % 3600) // 60)
    secondi = int(uptime_seconds % 60)

    parts = []
    if giorni > 0:
        parts.append(f"{giorni} {'giorno' if giorni == 1 else 'giorni'}")
    if ore > 0:
        parts.append(f"{ore} {'ora' if ore == 1 else 'ore'}")
    if minuti > 0:
        parts.append(f"{minuti} {'minuto' if minuti == 1 else 'minuti'}")
    if secondi > 0 or not parts:
        parts.append(f"{secondi} {'secondo' if secondi == 1 else 'secondi'}")

    return ', '.join(parts)


def check_model_name():
    full_cmd = "cat /sys/firmware/devicetree/base/model"
    model_name = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8")
    if model_name == '':
        full_cmd = "cat /proc/cpuinfo  | grep 'name'| uniq"
        model_name = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8")
        try:
            model_name = model_name.split(':')[1].replace('\n', '')
        except Exception:
            model_name = 'unknown'

    try:
        with open('/proc/meminfo', 'r') as meminfo_file:
            for line in meminfo_file:
                if line.startswith('MemTotal'):
                    total_ram_kb = int(line.split()[1])  # Estrae la memoria totale in KB
                    break
            else:
                total_ram_kb = None  # Se 'MemTotal' non è trovato
    except Exception as e:
        print(f"Errore durante la lettura della memoria: {e}")
        total_ram_kb = None

    if total_ram_kb:
        total_ram_gb = total_ram_kb / 1024 / 1024  # Converti KB a GB
        if total_ram_gb < 1.5:
            ram_str = '1 GB'
        elif 1.5 <= total_ram_gb < 3.5:
            ram_str = '2 GB'
        elif 3.5 <= total_ram_gb < 6.5:
            ram_str = '4 GB'
        elif total_ram_gb >= 6.5:
            ram_str = '8 GB'
        else:
            ram_str = ''
    else:
        ram_str = ''

    if ram_str:
        return model_name + ' - ' + ram_str
    else:
        return model_name


def check_rpi5_fan_speed():
    full_cmd = "cat /sys/devices/platform/cooling_fan/hwmon/*/fan1_input"
    rpi5_fan_speed = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8").strip()

    return rpi5_fan_speed


def get_os():
    full_cmd = 'cat /etc/os-release | grep -i pretty_name'
    pretty_name = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8")
    try:
        pretty_name = pretty_name.split('=')[1].replace('"', '').replace('\n', '')
    except Exception:
        pretty_name = 'Unknown'
        
    return(pretty_name)


def get_manufacturer():
    try:
        if 'Raspberry' not in check_model_name():
            full_cmd = "cat /proc/cpuinfo  | grep 'vendor'| uniq"
            pretty_name = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8")
            pretty_name = pretty_name.split(':')[1].replace('\n', '')
        else:
            pretty_name = 'Raspberry Pi'
    except Exception:
        pretty_name = 'unknown'
        
    return(pretty_name)


def get_kernel_version():
    full_cmd = 'uname -r'
    kernel_version = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8")
    try:
        kernel_version = kernel_version.strip()
    except Exception:
        kernel_version = 'unknown'
        
    return kernel_version


def get_system_updates():
    full_cmd = "sudo apt-get update"
    try:
        update_process = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8")
    except Exception:
        print(f"Errore durante l'esecuzione di 'apt-get update'")

    check_system_updates()

    return


def check_system_updates():
    full_cmd = "apt list --upgradable 2>/dev/null | grep -c 'upgradable'"
    try:
        system_updates = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8").strip()
        system_updates = int(system_updates)
    except Exception:
        system_updates = 'unknown'

    return system_updates


def install_system_updates():
    full_cmd = "sudo apt-get update && sudo apt-get -y upgrade && sudo apt-get -y dist-upgrade && sudo apt-get -y autoremove"
    
    try:
        publish_system_update_progress("Inizio dell'installazione degli aggiornamenti...")
        print("Inizio dell'installazione degli aggiornamenti...")
        process = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

        for line in iter(process.stdout.readline, ''):
            if line:
                publish_system_update_progress(line.strip())
                print(line.strip())

        process.stdout.close()
        process.wait()

        if process.returncode == 0:
            result = "Aggiornamento completato con successo!"
        else:
            result = f"Errore durante l'aggiornamento: codice di ritorno {process.returncode}"
        
    except Exception as e:
        result = f"Eccezione durante l'aggiornamento: {str(e)}"
    
    print(result)
    publish_system_update_progress(result)
    system_update_info = check_system_updates()
    publish_system_update_status_to_mqtt(system_update_info)

    return result

def get_upgradable_packages():
    full_cmd = "apt list --upgradable 2>/dev/null | grep 'upgradable' | awk -F/ '{print $1}'"
    try:
        # Esegui il comando e cattura l'output
        packages = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8").strip()
        
        # Controlla se ci sono pacchetti aggiornabili
        if packages:
            # Trasforma la lista dei pacchetti in una stringa separata da virgola
            package_list = packages.split('\n')
            package_str = ', '.join(package_list)
        else:
            package_str = 'No upgradable packages'
    
    except Exception:
        package_str = 'Error while checking for updates'

    return package_str


def get_system_architecture():
    full_cmd = 'uname -m'
    try:
        architecture = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8").strip()
    except Exception:
        architecture = 'unknown'
        
    return architecture


def get_cpu_info():
    try:
        lscpu_output = subprocess.Popen("lscpu", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].decode("utf-8")
        core_count = 0
        core_model = None
        for line in lscpu_output.splitlines():
            if "CPU(s):" in line and "NUMA" not in line:
                core_count = int(line.split(":")[1].strip())
            elif "Model name:" in line or "Core(s) per socket:" in line:
                core_model = line.split(":")[1].strip()
        
        if core_model is not None:
            cpu_info = f"{core_count} x {core_model}"
        else:
            cpu_info = f"{core_count} cores"

        return cpu_info

    except Exception as e:
        print(f"Errore durante il recupero delle informazioni sulla CPU: {e}")
        return "unknown"


def get_network_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def get_mac_address():
    mac_num = uuid.getnode()
    mac = '-'.join((('%012X' % mac_num)[i:i+2] for i in range(0, 12, 2)))
    return mac


def print_measured_values(used_space=0, sys_clock_speed=0, swap=0, memory=0,
                          uptime=0, uptime_seconds=0, wifi_signal=0, wifi_signal_dbm=0, rpi5_fan_speed=0,
                          os_version=0, manufacturer=0, model_name=0, kernel_version=0, system_updates=0, system_arch=0, upgradable_packages=0):
    get_system_updates()
    output = """
:: rpi-mqtt-monitor
   Version: {}

:: Device Information
   Model Name: {}
   Manufacturer: {}
   OS: {}
   Hostname: {}
   IP Address: {}
   MAC Address: {}
""".format(config.version, check_model_name(), get_manufacturer(), get_os(), hostname, get_network_ip(), get_mac_address())

    if args.service:
        output += "   Service Sleep Time: {} seconds\n".format(config.service_sleep_time)
    output += """
:: Measured values
   Disk Usage: {} %
   CPU Clock Speed: {} MHz
   Swap: {} %
   Memory: {} %
   Uptime: {}
   Uptime (Seconds): {}
   Wifi Signal: {} %
   Wifi Signal dBm: {}
   RPI5 Fan Speed: {} RPM
   OS: {}
   Kernel: {}
   Architecture: {}
   System updates: {}
   Upgradable packages: {}
""".format(used_space, sys_clock_speed, swap, memory, uptime, uptime_seconds, wifi_signal, wifi_signal_dbm, rpi5_fan_speed, os_version, kernel_version, system_arch, check_system_updates(), upgradable_packages)
    output += "\r\nInstallation directory: {}\n".format(script_dir)
    print(output)


def extract_text(html_string):
    html_string = html.unescape(html_string)
    text = re.sub('<[^<]+?>', '', html_string)

    return text


def config_json(what_config):
    model_name = check_model_name()
    manufacturer = get_manufacturer()
    os = get_os()
    data = {
        "state_topic": "",
        "icon": "",
        "name": "",
        "unique_id": "",

        "device": {
            "identifiers": [hostname],
            "manufacturer": 'github.com/systempal',
            "model": 'RPi MQTT Monitor PLus ' + config.version,
            "name": hostname,
            "configuration_url": "https://github.com/systempal/rpi-mqtt-monitor-plus"
        }
    }

    data["state_topic"] = config.mqtt_topic_prefix + "/" + hostname + "/" + what_config
    data["unique_id"] = hostname + "_" + what_config
    if what_config == "cpuload":
        data["icon"] = "mdi:speedometer"
        data["name"] = "CPU Usage"
        data["state_class"] = "measurement"
        data["unit_of_measurement"] = "%"
    elif what_config == "os_version":
        data["icon"] = "mdi:linux"
        data["name"] = "OS"
    elif what_config == "manufacturer":
        data["icon"] = "mdi:server-network"
        data["name"] = "Manufaturer"
    elif what_config == "model_name":
        data["icon"] = "mdi:credit-card-settings-outline"
        data["name"] = "Model Name"
    elif what_config == "kernel_version":
        data["icon"] = "mdi:linux"
        data["name"] = "Kernel"
    elif what_config == "system_updates":
        data["icon"] = "mdi:linux"
        data["name"] = "Updates"
    elif what_config == "system_arch":
        data["icon"] = "mdi:linux"
        data["name"] = "Architecture"
    elif what_config == "upgradable_packages":
        data["icon"] = "mdi:package-variant"
        data["name"] = "Upgradable packages"
    elif what_config == "cputemp":
        data["icon"] = "hass:thermometer"
        data["name"] = "CPU Temperature"
        data["unit_of_measurement"] = "°C"
        data["state_class"] = "measurement"
    elif what_config == "diskusage":
        data["icon"] = "mdi:harddisk"
        data["name"] = "Disk Usage"
        data["unit_of_measurement"] = "%"
        data["state_class"] = "measurement"
    elif what_config == "swap":
        data["icon"] = "mdi:harddisk"
        data["name"] = "Disk Swap"
        data["unit_of_measurement"] = "%"
        data["state_class"] = "measurement"
    elif what_config == "memory":
        data["icon"] = "mdi:memory"
        data["name"] = "Memory Usage"
        data["unit_of_measurement"] = "%"
        data["state_class"] = "measurement"
    elif what_config == "sys_clock_speed":
        data["icon"] = "mdi:speedometer"
        data["name"] = "CPU Clock Speed"
        data["unit_of_measurement"] = "MHz"
        data["state_class"] = "measurement"
    elif what_config == "uptime":
        data["icon"] = "mdi:calendar"
        data["name"] = "Uptime"
#        data["unit_of_measurement"] = ""
#        data["state_class"] = "total_increasing"
    elif what_config == "uptime_seconds":
        data["icon"] = "mdi:timer-outline"
        data["name"] = "Uptime seconds"
        data["unit_of_measurement"] = "s"
        data["device_class"] = "duration"
        data["state_class"] = "total_increasing"
    elif what_config == "wifi_signal":
        data["icon"] = "mdi:wifi"
        data["name"] = "Wifi Signal"
        data["unit_of_measurement"] = "%"
        data["state_class"] = "measurement"
    elif what_config == "wifi_signal_dbm":
        data["icon"] = "mdi:wifi"
        data["name"] = "Wifi Signal"
        data["unit_of_measurement"] = "dBm"
        data["state_class"] = "measurement"
    elif what_config == "rpi5_fan_speed":
        data["icon"] = "mdi:fan"
        data["name"] = "Fan Speed"
        data["unit_of_measurement"] = "RPM"
        data["state_class"] = "measurement"
    elif what_config == "status":
        data["icon"] = "mdi:lan-connect"
        data["name"] = "Status"
        data["value_template"] = "{{ 'online' if value == '1' else 'offline' }}"
    elif what_config == "restart_button":
        data["icon"] = "mdi:restart"
        data["name"] = "System Restart"
        data["command_topic"] = "homeassistant/update/" + hostname + "/command"
        data["payload_press"] = "restart"
        data["device_class"] = "restart"
    elif what_config == "shutdown_button":
        data["icon"] = "mdi:power"
        data["name"] = "System Shutdown"
        data["command_topic"] = "homeassistant/update/" + hostname + "/command"
        data["payload_press"] = "shutdown"
        data["device_class"] = "restart"
    elif what_config == "install_system_updates":
        data["icon"] = "mdi:update"
        data["name"] = "Install system updates"
        data["command_topic"] = "homeassistant/update/" + hostname + "/command"
        data["payload_press"] = "install_system_updates"
        data["device_class"] = "update"
    elif what_config == "check_system_updates_button":
        data["icon"] = "mdi:update"
        data["name"] = "Check System Updates"
        data["command_topic"] = "homeassistant/update/" + hostname + "/command"
        data["payload_press"] = "check_system_updates"
        data["device_class"] = "update"
    elif what_config == "system_update_progress":
        data["icon"] = "mdi:progress-alert"
        data["name"] = "System Update Progress"

    else:
        return ""
    # Return our built discovery config
    return json.dumps(data)


def create_mqtt_client():

    def on_log(client, userdata, level, buf):
        if level == paho.MQTT_LOG_ERR:
            print("MQTT error: ", buf)


    def on_connect(client, userdata, flags, rc):
        if rc != 0:
            print("Error: Unable to connect to MQTT broker, return code:", rc)


    client = paho.Client(client_id="rpi-mqtt-monitor-" + hostname + str(int(time.time())))
    client.username_pw_set(config.mqtt_user, config.mqtt_password)
    client.on_log = on_log
    client.on_connect = on_connect
    try:
        client.connect(config.mqtt_host, int(config.mqtt_port))
    except Exception as e:
        print("Error connecting to MQTT broker:", e)
        return None
    return client


def publish_system_update_status_to_mqtt(system_updates_info):

    client = create_mqtt_client()
    if client is None:
        print("Error: Unable to connect to MQTT broker")
        return

    client.loop_start()
    
    client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_system_updates/config", config_json('system_updates'), qos=config.qos)
    client.publish(config.mqtt_topic_prefix + "/" + hostname + "/system_updates", system_updates_info, qos=config.qos, retain=config.retain)

    upgradable_packages = get_upgradable_packages()
    client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_upgradable_packages/config", config_json('upgradable_packages'), qos=config.qos)
    client.publish(config.mqtt_topic_prefix + "/" + hostname + "/upgradable_packages", upgradable_packages, qos=config.qos, retain=config.retain)

    while len(client._out_messages) > 0:
        time.sleep(0.1)
        client.loop()

    client.loop_stop()
    client.disconnect()


def publish_system_update_progress(message):
    client = create_mqtt_client()
    if client is None:
        print("Error: Unable to connect to MQTT broker")
        return

    client.loop_start()

    # Pubblica il messaggio sul topic specifico
    client.publish(config.mqtt_topic_prefix + "/" + hostname + "/system_update_progress", message, qos=config.qos, retain=config.retain)

    while len(client._out_messages) > 0:
        time.sleep(0.1)
        client.loop()

    client.loop_stop()
    client.disconnect()


def publish_to_mqtt(used_space=0, sys_clock_speed=0, swap=0, memory=0,
                    uptime=0, uptime_seconds=0, wifi_signal=0, wifi_signal_dbm=0, rpi5_fan_speed=0,
                    os_version=0, manufacturer=0, model_name=0, kernel_version=0, system_updates=0, system_arch=0, upgradable_packages=0):

    client = create_mqtt_client()
    if client is None:
        return

    client.loop_start()


    if config.system_updates:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_system_updates/config", config_json('system_updates'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/system_updates", system_updates, qos=config.qos, retain=config.retain)
    if config.system_updates:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_upgradable_packages/config", config_json('upgradable_packages'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/upgradable_packages", upgradable_packages, qos=config.qos, retain=config.retain)
    if config.os_version:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_os_version/config", config_json('os_version'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/os_version", os_version, qos=config.qos, retain=config.retain)
    if config.manufacturer_info:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_manufacturer/config", config_json('manufacturer'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/manufacturer", manufacturer, qos=config.qos, retain=config.retain)
    if config.model_name:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_model_name/config", config_json('model_name'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/model_name", model_name, qos=config.qos, retain=config.retain)
    if config.kernel_version:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_kernel_version/config", config_json('kernel_version'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/kernel_version", kernel_version, qos=config.qos, retain=config.retain)
    if config.system_architecture:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_system_arch/config", config_json('system_arch'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/system_arch", system_arch, qos=config.qos, retain=config.retain)
    if config.disk_usage:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_diskusage/config", config_json('diskusage'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/diskusage", used_space, qos=config.qos, retain=config.retain)
    if config.swap_usage:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_swap/config", config_json('swap'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/swap", swap, qos=config.qos, retain=config.retain)
    if config.memory_usage:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_memory/config", config_json('memory'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/memory", memory, qos=config.qos, retain=config.retain)
    if config.cpu_clock_speed:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_sys_clock_speed/config", config_json('sys_clock_speed'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/sys_clock_speed", sys_clock_speed, qos=config.qos, retain=config.retain)
    if config.uptime:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_uptime/config", config_json('uptime'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/uptime", uptime, qos=config.qos, retain=config.retain)
    if config.uptime_seconds:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_uptime_seconds/config", config_json('uptime_seconds'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/uptime_seconds", uptime_seconds, qos=config.qos, retain=config.retain)
    if config.wifi_signal:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_wifi_signal/config", config_json('wifi_signal'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/wifi_signal", wifi_signal, qos=config.qos, retain=config.retain)
    if config.wifi_signal_dbm:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_wifi_signal_dbm/config", config_json('wifi_signal_dbm'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/wifi_signal_dbm", wifi_signal_dbm, qos=config.qos, retain=config.retain)
    if config.rpi5_fan_speed:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_rpi5_fan_speed/config", config_json('rpi5_fan_speed'), qos=config.qos)
        client.publish(config.mqtt_topic_prefix + "/" + hostname + "/rpi5_fan_speed", rpi5_fan_speed, qos=config.qos, retain=config.retain)
    if config.restart_button:
        client.publish("homeassistant/button/" + config.mqtt_topic_prefix + "/" + hostname + "_restart/config", config_json('restart_button'), qos=config.qos)
    if config.shutdown_button:
        client.publish("homeassistant/button/" + config.mqtt_topic_prefix + "/" + hostname + "_shutdown/config", config_json('shutdown_button'), qos=config.qos)
    if config.check_updates_button:
        client.publish("homeassistant/button/" + config.mqtt_topic_prefix + "/" + hostname + "_check_system_updates/config", config_json('check_system_updates_button'), qos=config.qos )
    if config.install_updates_button:
        client.publish("homeassistant/button/" + config.mqtt_topic_prefix + "/" + hostname + "_install_system_updates/config", config_json('install_system_updates'), qos=config.qos)
    if config.system_update_progress:
        client.publish("homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_system_update_progress/config", config_json('system_update_progress'), qos=config.qos)


    status_sensor_topic = "homeassistant/sensor/" + config.mqtt_topic_prefix + "/" + hostname + "_status/config"
    client.publish(status_sensor_topic, config_json('status'), qos=config.qos)
    client.publish(config.mqtt_topic_prefix + "/" + hostname + "/status", "1", qos=config.qos, retain=config.retain)
    
    while len(client._out_messages) > 0:
        time.sleep(0.1)
        client.loop()

    client.loop_stop()
    client.disconnect()


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--display', action='store_true', help='display values on screen', default=False)
    parser.add_argument('-s', '--service', action='store_true', help='run script as a service, sleep interval is configurable in config.py', default=False)
    parser.add_argument('-v', '--version', action='store_true', help='display installed version and exit', default=False)
    args = parser.parse_args()

    if args.version:
        installed_version = config.version
        print("Installed version: " + installed_version)
        exit()

    return args


def collect_monitored_values():
    used_space = sys_clock_speed = swap = memory = uptime_seconds = uptime = wifi_signal = wifi_signal_dbm = rpi5_fan_speed = os_version = manufacturer = model_name = kernel_version = system_updates = system_arch = upgradable_packages = False

    if config.disk_usage:
        used_space = check_used_space(config.disk_usage_path)
    if config.cpu_clock_speed:
        sys_clock_speed = check_sys_clock_speed()
    if config.swap_usage:
        swap = check_swap()
    if config.memory_usage :
        memory = check_memory()
    if config.uptime:
        uptime = check_uptime_str()
    if config.uptime_seconds:
        uptime_seconds = check_uptime('')
    if config.wifi_signal:
        wifi_signal = check_wifi_signal('')
    if config.wifi_signal_dbm:
        wifi_signal_dbm = check_wifi_signal('dbm')
    if config.rpi5_fan_speed:
        rpi5_fan_speed = check_rpi5_fan_speed()
    if config.os_version:
        os_version = get_os()
    if config.manufacturer_info:
        manufacturer = get_manufacturer()
    if config.model_name:
        model_name = check_model_name()
    if config.kernel_version:
        kernel_version = get_kernel_version()
    if config.system_updates:
        system_updates = check_system_updates()
        upgradable_packages = get_upgradable_packages()
    if config.system_architecture:
        system_arch = get_system_architecture()

    return used_space, sys_clock_speed, swap, memory, uptime, uptime_seconds, wifi_signal, wifi_signal_dbm, rpi5_fan_speed, os_version, manufacturer, model_name, kernel_version, system_updates, system_arch, upgradable_packages


def gather_and_send_info():
    while not stop_event.is_set():
        used_space, sys_clock_speed, swap, memory, uptime, uptime_seconds, wifi_signal, wifi_signal_dbm, rpi5_fan_speed, os_version, manufacturer, model_name, kernel_version, system_updates, system_arch, upgradable_packages = collect_monitored_values()

        if hasattr(config, 'random_delay'):
            time.sleep(config.random_delay)

        if args.display:
            print_measured_values(used_space, sys_clock_speed, swap, memory, uptime, uptime_seconds, wifi_signal, wifi_signal_dbm, rpi5_fan_speed, os_version, manufacturer, model_name, kernel_version, system_updates, system_arch, upgradable_packages)

        publish_to_mqtt(used_space, sys_clock_speed, swap, memory, uptime, uptime_seconds, wifi_signal, wifi_signal_dbm, rpi5_fan_speed, os_version, manufacturer, model_name, kernel_version, system_updates, system_arch, upgradable_packages)

        if not args.service:
            break
        # Break the sleep into 1-second intervals and check stop_event after each interval
        for _ in range(config.service_sleep_time):
            if stop_event.is_set():
                break
            time.sleep(1)


def system_update_status():
    while not stop_event.is_set():
        get_system_updates()
        system_update_info = check_system_updates()
        publish_system_update_status_to_mqtt(system_update_info)
        stop_event.wait(config.updates_check_interval)
        if stop_event.is_set():
            break

def on_message(client, userdata, msg):
    global exit_flag, thread1, thread3
    print("Received message: ", msg.payload.decode())
    if msg.payload.decode() == "restart":
        print("Restarting the system...")
        os.system("sudo reboot")
    elif msg.payload.decode() == "shutdown":
        print("Shutting down the system...")
        os.system("sudo shutdown now")
    elif msg.payload.decode() == "install_system_updates":
#        print("Avvio dell'installazione degli aggiornamenti...")
#        publish_system_update_progress("Avvio dell'installazione degli aggiornamenti...")
        install_system_updates()
#        publish_system_update_progress("Aggiornamento completato.")
#        print("Aggiornamento completato.")
    elif msg.payload.decode() == "check_system_updates":
        print("Checking for system updates...")
        get_system_updates()
        system_update_info = check_system_updates()
        publish_system_update_status_to_mqtt(system_update_info)
        print("System update status published.")

exit_flag = False
stop_event = threading.Event()
script_dir = os.path.dirname(os.path.realpath(__file__))
# get device host name - used in mqtt topic
# and adhere to the allowed character set
hostname = re.sub(r'[^a-zA-Z0-9_-]', '_', socket.gethostname())

if __name__ == '__main__':
    args = parse_arguments();
    if args.service:
        client = paho.Client()
        client.username_pw_set(config.mqtt_user, config.mqtt_password)
        client.on_message = on_message
        # set will_set to send a message when the client disconnects
        client.will_set(config.mqtt_topic_prefix + "/" + hostname + "/status", "0", qos=config.qos, retain=config.retain)
        try:
            client.connect(config.mqtt_host, int(config.mqtt_port))
        except Exception as e:
            print("Error connecting to MQTT broker:", e)
            sys.exit(1)

        client.subscribe("homeassistant/update/" + hostname + "/command")
        print("Listening to topic : " + "homeassistant/update/" + hostname + "/command")
        client.loop_start()
        thread1 = threading.Thread(target=gather_and_send_info)
        thread1.daemon = True  # Set thread1 as a daemon thread
        thread1.start()

        if config.system_updates:
            thread3 = threading.Thread(target=system_update_status)
            thread3.daemon = True  # Set thread3 as a daemon thread
            thread3.start()

        try:
            while True:
                time.sleep(1)  # Check the exit flag every second
        except KeyboardInterrupt:
            print(" Ctrl+C pressed. Setting exit flag...")
            client.loop_stop()
            exit_flag = True
            stop_event.set()  # Signal the threads to stop
            sys.exit(0)  # Exit the script
    else:
        gather_and_send_info()
