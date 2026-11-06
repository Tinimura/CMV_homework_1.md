#!/usr/bin/env python3
"""Збирає фактичні мережеві дані з поточної Linux-системи та формує звіт Markdown."""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess
import sys


def cmd(args, timeout=18):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        output = proc.stdout.strip()
        if proc.returncode != 0:
            return output, (proc.stderr.strip() or f"Код завершення: {proc.returncode}")
        return output, None
    except FileNotFoundError:
        return "", f"Команду «{args[0]}» не знайдено"
    except subprocess.TimeoutExpired:
        return "", "Перевищено час очікування виконання команди"
    except Exception as exc:
        return "", str(exc)


def as_json(args):
    output, error = cmd(args)
    if error:
        return [], error
    try:
        return json.loads(output), None
    except (json.JSONDecodeError, ValueError):
        return [], "Команда не повернула коректний JSON"


def cell(value):
    if value is None or value == "":
        return "**Не визначено; перевірити вручну**"
    return str(value).replace("|", "\\|").replace("\n", " ")


def parse_ip(value):
    try:
        return ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return None


def net_details(ip, prefix, broadcast_hint=None):
    try:
        ip_intf = ipaddress.IPv4Interface(f"{ip}/{prefix}")
        net = ip_intf.network
        size = net.num_addresses
        count = (size - 2) if net.prefixlen <= 30 else size
        if net.prefixlen <= 30:
            first = net.network_address + 1
            last = net.broadcast_address - 1
        else:
            first, last = net.network_address, net.broadcast_address
        return {
            "mask": str(net.netmask),
            "prefix": prefix,
            "network": str(net.network_address),
            "broadcast": broadcast_hint or str(net.broadcast_address),
            "hosts": f"{count} придатних адрес ({first}–{last})",
        }
    except (ValueError, ipaddress.AddressValueError):
        return {"mask": None, "prefix": prefix, "network": None, "broadcast": broadcast_hint, "hosts": None}


def connection_type(name):
    if not name:
        return None
    try:
        if (Path("/sys/class/net") / name / "wireless").exists() or name.startswith(("wl", "wlan")):
            return "Бездротове з'єднання (Wi-Fi)"
        if name.startswith(("en", "eth")):
            return "Ethernet; фізичний чи віртуальний адаптер потрібно перевірити окремо"
        if name.startswith(("tun", "tap", "wg")):
            return "Віртуальний інтерфейс (тунель/VPN)"
        if name.startswith(("veth", "br", "docker")):
            return "Віртуальний мережевий інтерфейс"
    except OSError:
        pass
    return "Тип підключення потребує перевірки (назви інтерфейсу недостатньо)"


def route_explanation(protocol, iface_dynamic):
    if protocol == "dhcp":
        base = "У маршруті зазначено `proto dhcp`: маршрут отримано через DHCP."
        if iface_dynamic:
            base += " Прапорець `dynamic` у виводі `ip a` додатково підтверджує динамічну адресу."
        return base
    if protocol == "static":
        return ("У маршруті зазначено `proto static`: маршрут позначено як статичний. "
                "Це **не є однозначним доказом** ручного налаштування IP-адреси, "
                "оскільки спосіб її отримання визначається окремо.")
    if protocol == "kernel":
        return ("У маршруті зазначено `proto kernel`: маршрут до безпосередньо підключеної мережі "
                "створило ядро Linux. За цим записом **не можна** визначити, чи IP надано DHCP.")
    if protocol:
        return (f"У таблиці маршрутизації вказано `proto {protocol}`. Цей параметр описує "
                "походження маршруту, а не обов'язково спосіб отримання IP-адреси.")
    return ("Для основного маршруту параметр `proto` не вказано. "
            "Команда `ip r` сама по собі не дозволяє надійно встановити, "
            "чи адресу видано через DHCP; для уточнення слід перевірити налаштування мережевого менеджера.")


def compare_ip(local_ip, pub_ip):
    if not local_ip or not pub_ip:
        return ("Коректне порівняння поки неможливе: відсутня одна з IP-адрес. "
                "Потрібно повторити команди та вписати фактичні результати.")
    if local_ip.version != pub_ip.version:
        return ("Адреси належать до різних версій IP, тому пряме числове порівняння некоректне. "
                "Потрібно отримати публічну адресу тієї самої версії протоколу (для IPv4 — `curl -4 ifconfig.io`).")
    if local_ip == pub_ip:
        return ("**Так, адреси збігаються.** На цьому інтерфейсі вказано таку саму адресу, "
                "яку бачить зовнішній сервіс. Це не доводить відсутності фаєрвола чи інших мережевих посередників.")
    private4 = isinstance(local_ip, ipaddress.IPv4Address) and any(
        local_ip in block for block in [ipaddress.ip_network('10.0.0.0/8'),
                                     ipaddress.ip_network('172.16.0.0/12'),
                                     ipaddress.ip_network('192.168.0.0/16')]
    )
    if private4:
        return ("**Ні, адреси різні.** Локальна IPv4-адреса належить до приватного діапазону RFC 1918 "
                "і не маршрутизується напряму у публічному Інтернеті. Під час виходу назовні "
                "маршрутизатор або інший мережевий шлюз зазвичай використовує трансляцію адрес "
                "(NAT). Тому сервіс `ifconfig.io` бачить зовнішню адресу шлюзу, а не адресу "
                "мережевого інтерфейсу комп'ютера. За наявності CGNAT або VPN додаткове "
                "перетворення може виконувати провайдер чи VPN-сервер; самі дві адреси "
                "не доводять, де саме відбувається NAT.")
    return ("**Ні, адреси різні.** Це можливо через NAT, VPN, проксі, кілька мережевих "
            "інтерфейсів або вихід через інший шлюз. За самими двома адресами неможливо "
            "однозначно довести конкретну причину; потрібно перевірити мережеву конфігурацію.")


def fenced_output(value, error, template):
    if template:
        return "[Вставити реальний вивід команди після виконання в Linux]"
    if error and not value:
        return f"[Команду не виконано: {error}]"
    return value or "[Вивід відсутній]"


def generate(template=False, surname="lastname", student=None):
    if template:
        raw_a = raw_r = raw_pub = ""
        err_a = err_r = err_pub = None
        addrs, routes = [], []
    else:
        raw_a, err_a = cmd(["ip", "a"])
        raw_r, err_r = cmd(["ip", "r"])
        # Саме запитана команда: curl ifconfig.io
        raw_pub, err_pub = cmd(["curl", "ifconfig.io"], timeout=20)
        addrs, addrs_err = as_json(["ip", "-j", "a"])
        routes, routes_err = as_json(["ip", "-j", "r"])
        if addrs_err:
            print("Попередження:", addrs_err, file=sys.stderr)
        if routes_err:
            print("Попередження:", routes_err, file=sys.stderr)

    default_routes = [r for r in routes if r.get("dst") in ("default", "0.0.0.0/0")]
    default_routes.sort(key=lambda r: r.get("metric", 0) if isinstance(r.get("metric", 0), int) else 0)
    chosen_route = default_routes[0] if default_routes else {}
    name = chosen_route.get("dev")
    iface_data = next((a for a in addrs if a.get("ifname") == name), None)
    if iface_data is None:
        iface_data = next((a for a in addrs if a.get("ifname") != "lo" and
                          any(x.get("family") == "inet" and x.get("scope") == "global"
                              for x in a.get("addr_info", []))), {})
        name = iface_data.get("ifname")
    ip_item = next((x for x in iface_data.get("addr_info", []) if
                    x.get("family") == "inet" and x.get("scope") == "global"), {})
    if not ip_item:
        ip_item = next((x for x in iface_data.get("addr_info", []) if x.get("family") == "inet"), {})
    ip_val = ip_item.get("local")
    prefix = ip_item.get("prefixlen")
    details = net_details(ip_val, prefix, ip_item.get("broadcast")) if ip_val else {}
    gateway = chosen_route.get("gateway")
    protocol = chosen_route.get("protocol")
    iface_dynamic = ("dynamic" in ip_item.get("flags", [])) or bool(ip_item.get("dynamic", False))
    mac = iface_data.get("address")
    public_val = (raw_pub.strip().splitlines() or [""])[0].strip()
    public_ip = parse_ip(public_val)
    comparable_pub = public_ip
    extra_public_v4 = None
    if not template and public_ip and public_ip.version == 6 and ip_val:
        v4_text, v4_err = cmd(["curl", "-4", "ifconfig.io"], timeout=20)
        extra_public_v4 = (v4_text, v4_err)
        possible = parse_ip(v4_text.strip().splitlines()[0] if v4_text.strip() else "")
        if possible and possible.version == 4:
            comparable_pub = possible
    if template:
        notes = ("**Це шаблон.** Дані у квадратних дужках потрібно замінити результатами "
                 "команд, виконаних на власній Linux-машині. Скрипт `generate_homework.py` може "
                 "автоматично створити заповнену версію.")
    else:
        notes = ("Результати отримано на комп’ютері з Linux, на якому запущено команди. "
                 "Перед здачею потрібно переконатися, що виконання команд завершилося "
                 "без помилок і що це потрібна мережа, а не контейнер чи VPN.")
    ip_text = f"{ip_val}/{prefix}" if ip_val is not None and prefix is not None else None
    route_table = '\n'.join([
        f"| Інтерфейс | {cell(name)} |",
        f"| Тип підключення | {cell(connection_type(name))} |",
        f"| MAC-адреса | {cell(mac)} (канальний рівень OSI, **2**) |" if mac else f"| MAC-адреса | {cell(None)} |",
        f"| IPv4-адреса | {cell(ip_text)} (мережевий рівень OSI, **3**) |",
        f"| Маска підмережі | {cell(details.get('mask'))}; префікс {chr(47) + str(prefix) if prefix is not None else cell(None)} (мережевий рівень OSI, **3**) |",
        f"| Gateway / шлюз за замовчуванням | {cell(gateway)} (мережевий рівень OSI, **3**) |",
        f"| Broadcast (IPv4) | {cell(details.get('broadcast'))} (мережевий рівень OSI, **3**) |",
        f"| Мережа | {cell(details.get('network'))} |",
        f"| Hosts / доступні адреси вузлів | {cell(details.get('hosts'))} |",
    ])
    proto_cell = "[вказати `proto dhcp`, `proto static`, `proto kernel` або «не вказано»]" if template else (f"`proto {protocol}`" if protocol else "`proto` не вказано")
    route_desc = ("[Після виконання команди з'ясувати походження маршруту; параметр `proto` "
                  "у таблиці маршрутів не завжди показує спосіб отримання IP-адреси.]" if template
                  else route_explanation(protocol, iface_dynamic))
    comparison = ("[Вказати, чи однакові адреси. Якщо локальна адреса приватна, пояснити "
                  "роль домашнього маршрутизатора і NAT; врахувати можливість VPN або CGNAT.]" if template
                  else compare_ip(parse_ip(ip_val) if ip_val else None, comparable_pub))
    pub_comparison = "[Публічна IPv4-адреса]" if template else (str(comparable_pub) if comparable_pub else "**Не вдалося визначити**")
    if extra_public_v4:
        extra_display = fenced_output(extra_public_v4[0], extra_public_v4[1], False)
        extra_section = ("\nОскільки `curl ifconfig.io` повернув IPv6-адресу, для коректного "
                         "порівняння з локальною IPv4-адресою додатково виконано:\n\n"
                         "```bash\ncurl -4 ifconfig.io\n```\n\n"
                         f"```text\n{extra_display}\n```\n")
    else:
        extra_section = ""
    src_ip = "[Локальна IPv4-адреса]" if template else (ip_val or "не визначено")
    markdown = f"""# Домашнє завдання № 1 — Основи комп'ютерних мереж

**ПІБ:** {student or '[Вказати прізвище, ім’я та по батькові]'}  
**Модуль:** 1. Основи комп’ютерних мереж

{notes}

## Завдання 1. Дослідження мережі (2 бали)

Виконана команда:

```bash
ip a
```

Результат команди:

```text
{fenced_output(raw_a, err_a, template)}
```

### Параметри мережевого підключення

| Параметр | Значення та пояснення |
|---|---|
{route_table}

**Пояснення:** IP-адреса та маска підмережі використовуються на **мережевому рівні OSI (3)** і визначають адресу вузла та межі підмережі. MAC-адреса працює на **канальному рівні OSI (2)**. Шлюз за замовчуванням передає пакети до мереж поза локальною підмережею. IPv4 broadcast — спеціальна адреса для широкомовної доставки пакетів у межах підмережі. Під **hosts** мається на увазі кількість адрес, доступних для вузлів, без адреси мережі та broadcast (для типових підмереж /30 і ширших).

## Завдання 2. Дослідження маршрутизації (2 бали)

Виконана команда:

```bash
ip r
```

Результат команди:

```text
{fenced_output(raw_r, err_r, template)}
```

**Основний маршрут:** шлюз {cell(gateway)}, інтерфейс {cell(name)}.  
**Протокол створення маршруту (`proto`):** {proto_cell}.

**Аналіз:** {route_desc}

Команда `ip r` відображає таблицю маршрутизації ядра Linux. Запис `default via ... dev ...` означає маршрут для пакетів, до адрес яких немає конкретнішого маршруту. Маршрут до локальної підмережі зазвичай позначено як `proto kernel`.

## Завдання 3. Знаходження публічної IP-адреси (2 бали)

Виконана команда:

```bash
curl ifconfig.io
```

Результат команди:

```text
{fenced_output(raw_pub, err_pub, template)}
```
{extra_section}
**Локальна IPv4-адреса:** {src_ip}.  
**Публічна IP-адреса для порівняння:** {pub_comparison}.

### Порівняння локальної та публічної адрес

{comparison}

## Висновок

Під час роботи з командами `ip a`, `ip r` та `curl ifconfig.io` досліджено налаштування мережевого інтерфейсу, маршрути до інших мереж і адресу, яку бачить зовнішній сервіс. Визначено роль IP-адреси, маски підмережі, шлюзу за замовчуванням і механізму NAT у IPv4-мережі.
"""
    file_surname = ''.join(c for c in surname.lower() if c.isalnum() or c in ('_', '-')) or 'lastname'
    out = Path.cwd() / "homework" / "module1" / f"{file_surname}_homework_1.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(markdown, encoding='utf-8')
    print(f"Збережено: {out}")
    if not template and (err_a or err_r or err_pub or not ip_val or not public_ip):
        print("Увага: частина даних не зібрана. Не завантажуйте звіт до перевірки.", file=sys.stderr)
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Формування звіту з основ комп’ютерних мереж")
    parser.add_argument("--surname", default="lastname", help="Прізвище латиницею для назви файлу")
    parser.add_argument("--student", default=None, help="ПІБ для заголовка")
    parser.add_argument("--template", action="store_true", help="Створити шаблон, не виконуючи команди")
    args = parser.parse_args()
    generate(args.template, args.surname, args.student)
