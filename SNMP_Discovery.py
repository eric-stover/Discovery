#!/usr/bin/env python3
"""
SNMP CIDR discovery (async) for network devices (Cisco-friendly) with optional SSH TCP precheck
and optional XML subnet ingestion + subnet metadata tagging.

Features:
- Async scanning of IPv4 CIDRs using SNMPv2c
- Optional fast TCP precheck to SSH (port 22 by default) before SNMP
- Collects hostname, serial (prefers chassis), model, sysObjectID, sysDescr
- Streams results to JSONL (low memory) and optional CSV
- Ingest subnets from XML files with <mod_ip_subnet_list> blocks
- Optional tagging of each discovered device with subnet metadata (name, VLAN, CIDR)
- Rescan from known devices JSONL
- Resume mode: skip IPs already in output JSONL
- Tunable concurrency, timeouts, retries

Requirements:
    pip install "pysnmp[asyncio]"

Tested with Python 3.10+.

Author: M365 Copilot for Eric Stover
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import logging
import os
import re
import signal
import sys
from typing import Dict, Iterable, List, Optional, Set, Tuple

from xml.etree import ElementTree as ET

from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectIdentity,
    ObjectType,
    getCmd,
    nextCmd,
)

# -------------------------
# OIDs used in collection
# -------------------------
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"    # sysName.0
OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"    # sysDescr.0
OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0" # sysObjectID.0

# ENTITY-MIB columns
OID_ENT_PHYSICAL_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"   # entPhysicalClass
OID_ENT_PHYSICAL_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11" # entPhysicalSerialNum
OID_ENT_PHYSICAL_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"  # entPhysicalModelName

ENT_CLASS_CHASSIS = 3  # chassis(3)

# -------------------------
# XML ingestion
# -------------------------

def _ensure_xml_root(xml_text: str) -> str:
    """
    If the file is a sequence of <mod_ip_subnet_list> ... </mod_ip_subnet_list> blocks
    without a single root, wrap with <root> ... </root> so ElementTree can parse it.
    """
    stripped = xml_text.strip()
    if stripped.startswith("<mod_ip_subnet_list>"):
        return f"<root>\n{xml_text}\n</root>"
    return xml_text

def parse_xml_subnets(paths: Iterable[str]) -> List[Dict[str, str]]:
    """
    Parse one or more XML files and return a list of dicts:
        {"cidr": "10.42.200.0/26", "name": "Pittsburgh ...", "vlan": "VLAN 1"}

    - Deduplicates by 'cidr' (last one wins for metadata if duplicates exist).
    - Tolerant of missing name/vlan fields.
    """
    entries: Dict[str, Dict[str, str]] = {}

    for p in paths:
        if not os.path.exists(p):
            logging.warning("XML file not found: %s (skipping)", p)
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                xml_text = f.read()
            xml_text = _ensure_xml_root(xml_text)
            root = ET.fromstring(xml_text)
        except Exception as e:
            logging.error("Failed to parse XML %s: %s", p, e)
            continue

        for node in root.findall(".//mod_ip_subnet_list"):
            def get(tag: str) -> Optional[str]:
                el = node.find(tag)
                return (el.text or "").strip() if el is not None else None

            cidr = get("ipsubnet_addr")
            name = get("ipsubnet_name") or ""
            vlan = get("CLASS_PARAM_vlan_number") or ""

            if not cidr:
                continue

            # basic sanity for CIDR
            try:
                _ = ipaddress.ip_network(cidr, strict=False)
            except Exception:
                logging.debug("Skipping invalid CIDR in XML: %s", cidr)
                continue

            entries[cidr] = {"cidr": cidr, "name": name, "vlan": vlan}

    return list(entries.values())

# -------------------------
# Helpers
# -------------------------

def vendor_from_sysobjectid(sysobj: str) -> Optional[str]:
    if not sysobj:
        return None
    enterprise_prefix = "1.3.6.1.4.1."
    if sysobj.startswith(enterprise_prefix):
        rest = sysobj[len(enterprise_prefix):]
        parts = rest.split(".")
        if parts and parts[0].isdigit():
            ent_num = int(parts[0])
            if ent_num == 9:
                return "Cisco"
            # Add more as needed: 2636 Juniper, 2011 Huawei, 8072 Net-SNMP, 14988 MikroTik, etc.
    return None


def csv_writer_init(csv_path: Optional[str], fieldnames: List[str]) -> Optional[csv.DictWriter]:
    if not csv_path:
        return None
    exists = os.path.exists(csv_path)
    f = open(csv_path, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    if not exists:
        writer.writeheader()
    writer._file_handle = f  # type: ignore
    return writer


def csv_writer_close(writer: Optional[csv.DictWriter]):
    if writer is None:
        return
    fh = getattr(writer, "_file_handle", None)
    if fh:
        fh.flush()
        fh.close()


def build_ip_to_subnet_map(
    subnet_entries: List[Dict[str, str]]
) -> Tuple[List[str], Dict[str, Dict[str, str]]]:
    """
    Expand given subnet entries into:
      - targets: list of IPs (host addresses only)
      - ip_to_meta: mapping ip -> {"subnet_cidr":..., "subnet_name":..., "vlan":...}

    Returns an empty mapping if no entries provided.
    """
    targets: List[str] = []
    ip_to_meta: Dict[str, Dict[str, str]] = {}

    for ent in subnet_entries:
        cidr = ent["cidr"]
        name = ent.get("name", "")
        vlan = ent.get("vlan", "")
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version != 4:
            continue
        meta = {"subnet_cidr": cidr, "subnet_name": name, "vlan": vlan}
        for ip in net.hosts():
            ip_str = str(ip)
            targets.append(ip_str)
            ip_to_meta[ip_str] = meta

    return targets, ip_to_meta


def expand_targets(
    cidr: Optional[str],
    input_jsonl: Optional[str],
    resume_jsonl: Optional[str],
    xml_subnets: Optional[List[str]],
) -> Tuple[List[str], Dict[str, Dict[str, str]]]:
    """
    Build targets from:
      - single --cidr (optional)
      - --xml-subnets files (optional)
      - --input-jsonl known devices (optional)
    Apply --resume-jsonl skipping already-completed IPs.
    Returns (targets, ip_to_meta) where ip_to_meta contains subnet metadata when available.
    """
    targets: List[str] = []
    ip_to_meta: Dict[str, Dict[str, str]] = {}
    known_done: Set[str] = set()

    if resume_jsonl and os.path.exists(resume_jsonl):
        logging.info("Resume mode: building set of completed IPs from %s", resume_jsonl)
        with open(resume_jsonl, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    ip = obj.get("ip")
                    if ip:
                        known_done.add(ip)
                except Exception:
                    continue
        logging.info("Resume mode: %d IPs already completed", len(known_done))

    # XML subnets first (they carry metadata)
    if xml_subnets:
        entries = parse_xml_subnets(xml_subnets)
        xml_targets, xml_ip_to_meta = build_ip_to_subnet_map(entries)
        for ip in xml_targets:
            if resume_jsonl and ip in known_done:
                continue
            targets.append(ip)
        ip_to_meta.update(xml_ip_to_meta)

    # Single CIDR (no metadata)
    if cidr:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version != 4:
            raise ValueError("Only IPv4 CIDRs are supported in this version.")
        for ip in net.hosts():
            ip_str = str(ip)
            if resume_jsonl and ip_str in known_done:
                continue
            targets.append(ip_str)

    # Known devices jsonl (no metadata)
    if input_jsonl:
        with open(input_jsonl, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                ip = obj.get("ip")
                if not ip:
                    continue
                if resume_jsonl and ip in known_done:
                    continue
                targets.append(ip)

    # De-dupe targets preserving order
    seen: Set[str] = set()
    deduped: List[str] = []
    for ip in targets:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)

    return deduped, ip_to_meta


# -------------------------
# TCP precheck (SSH) — fast full connect, immediate close
# -------------------------

async def tcp_port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        try:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
        return True
    except Exception:
        return False


# -------------------------
# SNMP Async functions
# -------------------------

async def snmp_get(
    engine: SnmpEngine,
    ip: str,
    community: str,
    timeout: int,
    retries: int,
    oids: List[str],
) -> Dict[str, Optional[str]]:
    result: Dict[str, Optional[str]] = {oid: None for oid in oids}

    try:
        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            engine,
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
            ContextData(),
            *[ObjectType(ObjectIdentity(oid)) for oid in oids],
        )

        if errorIndication:
            logging.debug("GET %s errorIndication=%s", ip, errorIndication)
            return result

        if errorStatus:
            logging.debug(
                "GET %s errorStatus=%s at %s",
                ip,
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            )
            return result

        for oid, val in varBinds:
            try:
                result[str(oid)] = str(val.prettyPrint())
            except Exception:
                result[str(oid)] = str(val)
    except Exception as e:
        logging.debug("GET %s exception: %s", ip, e)

    return result


async def snmp_walk_columns(
    engine: SnmpEngine,
    ip: str,
    community: str,
    timeout: int,
    retries: int,
    base_oids: List[str],
    max_rows: int = 0,
) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    try:
        async for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            engine,
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
            ContextData(),
            *[ObjectType(ObjectIdentity(oid)) for oid in base_oids],
            lexicographicMode=False,
        ):
            if errorIndication:
                logging.debug("WALK %s errorIndication=%s", ip, errorIndication)
                break
            if errorStatus:
                logging.debug(
                    "WALK %s errorStatus=%s at %s",
                    ip,
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                )
                break

            for oid, val in varBinds:
                try:
                    results.append((str(oid), str(val.prettyPrint())))
                except Exception:
                    results.append((str(oid), str(val)))

            if max_rows and len(results) >= max_rows:
                break
    except Exception as e:
        logging.debug("WALK %s exception: %s", ip, e)

    return results


def parse_ent_table(
    pairs: List[Tuple[str, str]]
) -> Tuple[Optional[str], Optional[str]]:
    rows: Dict[str, Dict[str, Optional[str]]] = {}

    def idx_from_oid(oid: str, base: str) -> Optional[str]:
        if oid.startswith(base + "."):
            return oid[len(base) + 1 :]
        return None

    for oid, val in pairs:
        idx = idx_from_oid(oid, OID_ENT_PHYSICAL_CLASS)
        if idx is not None:
            rows.setdefault(idx, {}).setdefault("class", None)
            try:
                if val.endswith(")"):
                    v = val.split("(")[-1].strip(")")
                    rows[idx]["class"] = str(int(v))
                else:
                    rows[idx]["class"] = str(int(val))
            except Exception:
                rows[idx]["class"] = None
            continue

        idx = idx_from_oid(oid, OID_ENT_PHYSICAL_SERIAL)
        if idx is not None:
            rows.setdefault(idx, {}).setdefault("serial", None)
            rows[idx]["serial"] = val if val != "None" else None
            continue

        idx = idx_from_oid(oid, OID_ENT_PHYSICAL_MODEL)
        if idx is not None:
            rows.setdefault(idx, {}).setdefault("model", None)
            rows[idx]["model"] = val if val != "None" else None
            continue

    chassis_serial = None
    chassis_model = None

    for _, data in rows.items():
        klass = data.get("class")
        serial = (data.get("serial") or "").strip()
        model = (data.get("model") or "").strip()
        try:
            klass_int = int(klass) if klass is not None else None
        except Exception:
            klass_int = None

        if klass_int == ENT_CLASS_CHASSIS:
            if serial and not chassis_serial:
                chassis_serial = serial
            if model and not chassis_model:
                chassis_model = model

    if chassis_serial is None:
        for data in rows.values():
            serial = (data.get("serial") or "").strip()
            if serial:
                chassis_serial = serial
                break

    model = chassis_model
    if model is None:
        for data in rows.values():
            m = (data.get("model") or "").strip()
            if m:
                model = m
                break

    return chassis_serial, model


async def probe_device(
    engine: SnmpEngine,
    ip: str,
    community: str,
    timeout: int,
    retries: int,
) -> Optional[Dict[str, str]]:
    scalars = await snmp_get(
        engine=engine,
        ip=ip,
        community=community,
        timeout=timeout,
        retries=retries,
        oids=[OID_SYSNAME, OID_SYSDESCR, OID_SYSOBJECTID],
    )

    sysname = scalars.get(OID_SYSNAME) or ""
    sysdescr = scalars.get(OID_SYSDESCR) or ""
    sysobjectid = scalars.get(OID_SYSOBJECTID) or ""

    if not (sysname or sysdescr or sysobjectid):
        return None

    pairs = await snmp_walk_columns(
        engine=engine,
        ip=ip,
        community=community,
        timeout=timeout,
        retries=retries,
        base_oids=[OID_ENT_PHYSICAL_CLASS, OID_ENT_PHYSICAL_SERIAL, OID_ENT_PHYSICAL_MODEL],
    )
    serial, model = parse_ent_table(pairs)

    device = {
        "ip": ip,
        "hostname": sysname.strip() or "",
        "serial": (serial or "").strip(),
        "model": (model or "").strip(),
        "sysObjectID": sysobjectid.strip(),
        "sysDescr": sysdescr.strip(),
        "vendor": vendor_from_sysobjectid(sysobjectid) or "",
    }
    return device


# -------------------------
# Orchestrator
# -------------------------

async def run_discovery(
    targets: List[str],
    community: str,
    jsonl_out: str,
    csv_out: Optional[str],
    workers: int,
    timeout: int,
    retries: int,
    ssh_precheck: bool,
    precheck_port: int,
    precheck_timeout: float,
    tag_with_subnet: bool,
    ip_to_meta: Dict[str, Dict[str, str]],
) -> None:
    os.makedirs(os.path.dirname(jsonl_out) or ".", exist_ok=True)
    jsonl_f = open(jsonl_out, "a", encoding="utf-8")

    base_fields = [
        "ip",
        "hostname",
        "serial",
        "model",
        "sysObjectID",
        "sysDescr",
        "vendor",
    ]
    subnet_fields = ["subnet_cidr", "subnet_name", "vlan"]
    fieldnames = base_fields + (subnet_fields if tag_with_subnet else [])

    csv_writer = csv_writer_init(csv_out, fieldnames)
    engine = SnmpEngine()
    stop_event = asyncio.Event()

    def _handle_sig(*_):
        logging.warning("Cancellation requested, finishing in-flight tasks...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_sig)
        except NotImplementedError:
            pass

    semaphore = asyncio.Semaphore(workers)

    async def worker(ip: str):
        async with semaphore:
            if stop_event.is_set():
                return
            try:
                # --- SSH TCP precheck (fast) ---
                if ssh_precheck:
                    open22 = await tcp_port_open(ip, precheck_port, precheck_timeout)
                    if not open22:
                        logging.info("SKIP %s  (TCP %d closed/no-ACK)", ip, precheck_port)
                        return

                # --- SNMP probe ---
                dev = await probe_device(engine, ip, community, timeout, retries)
                if dev:
                    if tag_with_subnet:
                        meta = ip_to_meta.get(ip, {})
                        # merge meta fields if available
                        dev.update({
                            "subnet_cidr": meta.get("subnet_cidr", ""),
                            "subnet_name": meta.get("subnet_name", ""),
                            "vlan": meta.get("vlan", ""),
                        })
                    # Write JSONL
                    jsonl_f.write(json.dumps(dev, ensure_ascii=False) + "\n")
                    jsonl_f.flush()
                    # Write CSV
                    if csv_writer:
                        csv_writer.writerow(dev)
                        csv_writer._file_handle.flush()  # type: ignore
                    logging.info(
                        "OK  %s  %s  %s  %s%s",
                        dev["ip"], dev["hostname"], dev["model"], dev["serial"],
                        f"  [{dev.get('subnet_name','') or dev.get('subnet_cidr','')}]"
                        if tag_with_subnet else ""
                    )
                else:
                    logging.info("NO  %s  (no SNMP response or no data)", ip)
            except Exception as e:
                logging.exception("ERR %s  %s", ip, e)

    tasks = [asyncio.create_task(worker(ip)) for ip in targets]

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    finally:
        jsonl_f.flush()
        jsonl_f.close()
        csv_writer_close(csv_writer)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Async SNMP CIDR discovery with optional SSH TCP precheck and XML subnet ingestion."
    )
    src = p.add_argument_group("Targets")
    src.add_argument("--cidr", help="IPv4 CIDR to scan, e.g. 10.0.0.0/16")
    src.add_argument("--xml-subnets", nargs="+", help="One or more XML files containing <mod_ip_subnet_list> blocks.")
    src.add_argument("--input-jsonl", help="JSONL file with known devices to rescan (expects objects with at least 'ip').")
    src.add_argument("--resume-jsonl", help="Existing JSONL output file; skip IPs already present in it.")

    snmp = p.add_argument_group("SNMP")
    snmp.add_argument("--community", required=True, help="SNMPv2c community string")

    out = p.add_argument_group("Output")
    out.add_argument("--jsonl-out", required=True, help="Output JSONL file (appends).")
    out.add_argument("--csv-out", help="Optional CSV output (appends).")
    out.add_argument("--tag-with-subnet", action="store_true", help="Include subnet metadata (from XML) in output rows.")

    perf = p.add_argument_group("Performance & Reliability")
    perf.add_argument("--workers", type=int, default=200, help="Max concurrent probes (default: 200)")
    perf.add_argument("--timeout", type=int, default=2, help="SNMP timeout per try in seconds (default: 2)")
    perf.add_argument("--retries", type=int, default=1, help="SNMP retries per request (default: 1)")
    perf.add_argument("--log", default="INFO", help="Log level: DEBUG, INFO, WARNING, ERROR")

    pre = p.add_argument_group("SSH TCP Precheck")
    pre.add_argument("--ssh-precheck", action="store_true",
                     help="Enable fast TCP precheck to SSH before SNMP (default: off)")
    pre.add_argument("--precheck-port", type=int, default=22, help="TCP port to precheck (default: 22)")
    pre.add_argument("--precheck-timeout", type=float, default=0.5,
                     help="TCP precheck timeout seconds (default: 0.5)")

    return p.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not any([args.cidr, args.input_jsonl, args.xml_subnets]):
        logging.error("Provide at least one of --cidr, --xml-subnets, or --input-jsonl")
        sys.exit(2)

    try:
        targets, ip_to_meta = expand_targets(
            cidr=args.cidr,
            input_jsonl=args.input_jsonl,
            resume_jsonl=args.resume_jsonl,
            xml_subnets=args.xml_subnets,
        )
    except Exception as e:
        logging.error("Target expansion failed: %s", e)
        sys.exit(2)

    if not targets:
        logging.warning("No targets to scan.")
        return

    logging.info(
        "Starting scan of %d targets with %d workers%s%s",
        len(targets),
        args.workers,
        " (SSH precheck enabled)" if args.ssh_precheck else "",
        " (subnet tagging)" if args.tag_with_subnet else "",
    )

    try:
        asyncio.run(
            run_discovery(
                targets=targets,
                community=args.community,
                jsonl_out=args.jsonl_out,
                csv_out=args.csv_out,
                workers=args.workers,
                timeout=args.timeout,
                retries=args.retries,
                ssh_precheck=args.ssh_precheck,
                precheck_port=args.precheck_port,
                precheck_timeout=args.precheck_timeout,
                tag_with_subnet=args.tag_with_subnet,
                ip_to_meta=ip_to_meta,
            )
        )
    except KeyboardInterrupt:
        logging.warning("Interrupted by user.")
    except Exception as e:
        logging.exception("Fatal error: %s", e)


if __name__ == "__main__":
    main()
