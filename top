#!/usr/bin/env python3
import curses
import os
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict

# Стили фигур Cisco для Draw.io
STYLES = {
    "cloud": "ellipse;shape=cloud;whiteSpace=wrap;html=1;strokeColor=#000000;fillColor=#ffffff;fontSize=14;",
    "router": "shape=mxgraph.cisco.routers_and_switches.router;fillColor=#005073;strokeColor=none;html=1;",
    "switch": "shape=mxgraph.cisco.routers_and_switches.workgroup_switch;fillColor=#005073;strokeColor=none;html=1;",
    "server": "shape=mxgraph.cisco.computers_and_peripherals.file_server;fillColor=#005073;strokeColor=none;html=1;",
    "client": "shape=mxgraph.cisco.computers_and_peripherals.ibm_mainframe;fillColor=#005073;strokeColor=none;html=1;",
}

SIZES = {
    "cloud": (140, 80),
    "router": (100, 65),
    "switch": (130, 65),
    "server": (65, 90),
    "client": (90, 85),
}

class NetworkScanner:
    def __init__(self):
        self.gateway_ip = self.detect_default_gateway()
        self.local_subnet = self.detect_local_subnet()
        self.discovered_hosts = []

    def detect_default_gateway(self):
        try:
            res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", res.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "192.168.1.1"

    def detect_local_subnet(self):
        try:
            res = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show"], capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if "scope global" in line:
                    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        return "192.168.1.0/24"

    def check_ports(self, ip, ports=(80, 443, 22, 445, 3389)):
        """Проверка открытых серверных портов"""
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.15)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        return open_ports

    def scan_network(self):
        hosts = []
        # Способ 1: Nmap (быстрый ping-sweep)
        try:
            cmd = ["nmap", "-sn", self.local_subnet, "-oX", "-"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            root = ET.fromstring(res.stdout)
            for h in root.findall("host"):
                if h.find("status") is not None and h.find("status").get("state") == "up":
                    addr = h.find("address[@addrtype='ipv4']")
                    if addr is not None:
                        hosts.append(addr.get("addr"))
        except Exception:
            # Способ 2: Чтение системного ARP-кэша Linux (/proc/net/arp)
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                            hosts.append(parts[0])
            except Exception:
                pass

        if self.gateway_ip not in hosts:
            hosts.append(self.gateway_ip)

        # Классификация узлов
        classified = []
        for ip in sorted(list(set(hosts))):
            if ip == self.gateway_ip:
                role = "router"
                label = f"RTR\n{ip}"
            else:
                open_ports = self.check_ports(ip)
                if len(open_ports) > 0:
                    role = "server"
                    label = f"SRV-{ip.split('.')[-1]}\n{ip}"
                else:
                    role = "client"
                    label = f"CLI-{ip.split('.')[-1]}\n{ip}"

            classified.append({"ip": ip, "role": role, "label": label})

        self.discovered_hosts = classified
        return classified


class DrawioGenerator:
    @staticmethod
    def build(hosts, gateway_ip, filename="network_topology.drawio"):
        levels = defaultdict(list)
        nodes = {}
        edges = []

        # 0. Облако WAN
        nodes["inet"] = {"label": "Inet", "role": "cloud"}
        levels[0].append("inet")

        # 1. Шлюз / Роутер
        nodes["rtr"] = {"label": f"RTR\n{gateway_ip}", "role": "router"}
        levels[1].append("rtr")
        edges.append(("inet", "rtr", ""))

        # 2. Виртуальные коммутаторы (SW-1 для серверов, SW-2 для клиентов)
        nodes["sw1"] = {"label": "SW-1 (Servers)", "role": "switch"}
        nodes["sw2"] = {"label": "SW-2 (Clients)", "role": "switch"}
        levels[2].extend(["sw1", "sw2"])
        edges.append(("rtr", "sw1", ""))
        edges.append(("rtr", "sw2", ""))

        # 3. Конечные узлы
        has_servers = False
        has_clients = False

        for h in hosts:
            if h["ip"] == gateway_ip:
                continue
            nid = f"host_{h['ip'].replace('.', '_')}"
            nodes[nid] = {"label": h["label"], "role": h["role"]}
            levels[3].append(nid)

            if h["role"] == "server":
                edges.append(("sw1", nid, "VLAN 10"))
                has_servers = True
            else:
                edges.append(("sw2", nid, "VLAN 20"))
                has_clients = True

        # Если какая-то ветка пустая, добавляем фиктивный узел для наглядности
        if not has_servers:
            nodes["srv_dummy"] = {"label": "SRV-1\n(Demo)", "role": "server"}
            levels[3].insert(0, "srv_dummy")
            edges.append(("sw1", "srv_dummy", "VLAN 10"))

        if not has_clients:
            nodes["cli_dummy"] = {"label": "CLI-1\n(Demo)", "role": "client"}
            levels[3].append("cli_dummy")
            edges.append(("sw2", "cli_dummy", "VLAN 20"))

        # Создание XML
        mxfile = ET.Element("mxfile", host="app.diagrams.net")
        diagram = ET.SubElement(mxfile, "diagram", name="Topology")
        model = ET.SubElement(diagram, "mxGraphModel", dx="1200", dy="900", grid="1", gridSize="10")
        root = ET.SubElement(model, "root")

        ET.SubElement(root, "mxCell", id="0")
        ET.SubElement(root, "mxCell", id="1", parent="0")

        # Расчет иерархических координат (Tree Layout)
        canvas_width = 1000
        base_y = 40
        y_spacing = 150

        for level_idx, node_ids in levels.items():
            count = len(node_ids)
            step_x = canvas_width // (count + 1)
            y = base_y + level_idx * y_spacing

            for i, nid in enumerate(node_ids):
                role = nodes[nid]["role"]
                w, h = SIZES[role]
                x = step_x * (i + 1) - (w // 2)

                # Фигура узла
                is_cloud = (role == "cloud")
                cell = ET.SubElement(root, "mxCell", {
                    "id": nid,
                    "value": nodes[nid]["label"] if is_cloud else "",
                    "style": STYLES[role],
                    "vertex": "1",
                    "parent": "1"
                })
                ET.SubElement(cell, "mxGeometry", x=str(x), y=str(y), width=str(w), height=str(h), as="geometry")

                # Подпись под фигурой
                if not is_cloud:
                    lbl = ET.SubElement(root, "mxCell", {
                        "id": f"{nid}_lbl",
                        "value": nodes[nid]["label"],
                        "style": "text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=12;fontStyle=1;",
                        "vertex": "1",
                        "parent": "1"
                    })
                    ET.SubElement(lbl, "mxGeometry", x=str(x - 20), y=str(y + h + 6), width=str(w + 40), height="30", as="geometry")

        # Связи (Edges)
        for idx, (src, dst, tag) in enumerate(edges):
            edge = ET.SubElement(root, "mxCell", {
                "id": f"edge_{idx}",
                "value": tag,
                "style": "endArrow=none;html=1;strokeColor=#000000;strokeWidth=1;labelBackgroundColor=#ffffff;",
                "edge": "1",
                "parent": "1",
                "source": src,
                "target": dst
            })
            ET.SubElement(edge, "mxGeometry", relative="1", as="geometry")

        tree = ET.ElementTree(mxfile)
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        return filename


def run_tui(stdscr):
    curses.curs_set(0)
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)

    scanner = NetworkScanner()
    status_msg = f"Готово к работе. Обнаружена сеть: {scanner.local_subnet}"
    
    menu_items = [
        "1. Сканировать локальную сеть",
        "2. Посмотреть найденные хосты",
        "3. Изменить целевую подсеть",
        "4. Экспортировать топологию в Draw.io",
        "5. Выход"
    ]
    current_row = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        # Шапка
        title = "=== NETWORK TOPOLOGY TO DRAW.IO SCANNER ==="
        stdscr.addstr(2, max(0, w // 2 - len(title) // 2), title, curses.A_BOLD)
        info = f"Шлюз: {scanner.gateway_ip} | Подсеть: {scanner.local_subnet} | Хостов в базе: {len(scanner.discovered_hosts)}"
        stdscr.addstr(3, max(0, w // 2 - len(info) // 2), info, curses.color_pair(2))

        # Отрисовка пунктов меню
        for idx, item in enumerate(menu_items):
            x = max(2, w // 2 - 20)
            y = 6 + idx
            if idx == current_row:
                stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
                stdscr.addstr(y, x, f" > {item} ")
                stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
            else:
                stdscr.addstr(y, x, f"   {item} ")

        # Статусная строка
        stdscr.addstr(h - 3, 2, "Состояние: " + status_msg[:w-15], curses.A_DIM)
        stdscr.addstr(h - 2, 2, "Навигация: [↑/↓] Выбор, [Enter] Подтвердить", curses.A_DIM)
        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            current_row = (current_row - 1) % len(menu_items)
        elif key == curses.KEY_DOWN:
            current_row = (current_row + 1) % len(menu_items)
        elif key in [curses.KEY_ENTER, 10, 13]:
            # 1. Сканировать
            if current_row == 0:
                status_msg = "Сканирование подсети... Пожалуйста, подождите."
                stdscr.addstr(h - 3, 2, "Состояние: " + status_msg, curses.A_BOLD)
                stdscr.refresh()
                hosts = scanner.scan_network()
                status_msg = f"Сканирование завершено. Найдено узлов: {len(hosts)}"

            # 2. Список хостов
            elif current_row == 1:
                stdscr.clear()
                stdscr.addstr(2, 2, "Список обнаруженных устройств:", curses.A_BOLD)
                if not scanner.discovered_hosts:
                    stdscr.addstr(4, 4, "Хосты не найдены. Сначала запустите сканирование.")
                else:
                    for i, hst in enumerate(scanner.discovered_hosts[:h-8]):
                        stdscr.addstr(4 + i, 4, f"{hst['ip']:<16} | Тип: {hst['role'].upper():<8} | Имя: {hst['label'].replace(chr(10), ' ')}")
                
                stdscr.addstr(h - 2, 2, "Нажмите любую клавишу для возврата...", curses.A_DIM)
                stdscr.refresh()
                stdscr.getch()

            # 3. Изменить подсеть
            elif current_row == 2:
                curses.echo()
                curses.curs_set(1)
                stdscr.clear()
                stdscr.addstr(3, 4, "Введите новую подсеть (например, 192.168.0.0/24): ")
                stdscr.refresh()
                sub = stdscr.getstr(4, 4, 30).decode('utf-8').strip()
                if sub:
                    scanner.local_subnet = sub
                    status_msg = f"Подсеть изменена на: {sub}"
                curses.noecho()
                curses.curs_set(0)

            # 4. Экспорт Draw.io
            elif current_row == 3:
                if not scanner.discovered_hosts:
                    # Если еще не сканировали, выполняем быстрое обнаружение
                    scanner.scan_network()

                filename = "topology.drawio"
                out = DrawioGenerator.build(scanner.discovered_hosts, scanner.gateway_ip, filename)
                status_msg = f"Схема успешно сохранена в файл: {os.path.abspath(out)}"

            # 5. Выход
            elif current_row == 4:
                break


if __name__ == "__main__":
    curses.wrapper(run_tui)
