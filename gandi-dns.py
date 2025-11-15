#!/usr/bin/env python

from __future__ import print_function

from argparse import ArgumentParser

try:
    import xmlrpclib
except ImportError:
    import xmlrpc.client as xmlrpclib

try:
    import urllib2 as request
except ImportError:
    from urllib import request


import sys
import socket

import netifaces as ni

# Production API
api = xmlrpclib.ServerProxy("https://rpc.gandi.net/xmlrpc/", verbose=False)

# Used to cache the zone_id for future calls
zone_id = None


def get_zone_id(opts):
    """Get the gandi.net ID for the current zone version"""

    global zone_id

    # If we've not already got the zone ID, get it
    if zone_id is None:
        # Get domain info then check for a zone
        domain_info = api.domain.info(opts.production_key, opts.domain_dame)
        current_zone_id = domain_info["zone_id"]

        if current_zone_id == "None":
            print("No zone - make sure domain is set to use gandi.net name servers.")
            sys.exit(1)

        zone_id = current_zone_id

    return zone_id


def get_zone_ip(opts):
    """Get the current IP from the A record in the DNS zone"""

    current_zone = api.domain.zone.record.list(
        opts.production_key, get_zone_id(opts), 0
    )
    ip = "0.0.0.0"
    # There may be more than one A record - we're interested in one with
    # the specific name (typically @ but could be sub domain)
    for d in current_zone:
        if d["type"] == "A" and d["name"] == opts.a_name:
            ip = d["value"]

    return ip


def get_local_ip(opts):
    if opts.interface is None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((opts.loc_ip_server, opts.loc_ip_port))
            return s.getsockname()[0]
        except Exception:
            print("[error] couldn't connect to socket", file=sys.stderr)
            sys.exit(1)
        finally:
            s.close()
    else:
        try:
            return get_all_ip_interfaces()[opts.interface]
        except KeyError:
            print(
                "[error] interface {} not found".format(opts.interface), file=sys.stderr
            )
            sys.exit(1)


def get_all_ip_interfaces():
    interfaces = ni.interfaces()
    ips = {
        interface: ni.ifaddresses(interface)[ni.AF_INET][0].get("addr", None)
        for interface in interfaces
        if len(ni.ifaddresses(interface)[ni.AF_INET][0]) > 0
    }
    return ips


def get_remote_ip(opts):
    """Get external IP"""

    try:
        # Could be any service that just gives us a simple
        # raw ASCII IP address (not HTML etc)
        result = request.urlopen(opts.ext_ip_server, timeout=3).read()
    except Exception:
        print("Unable to external IP address.")
        sys.exit(2)

    return result


def change_zone_ip(new_ip, opts):
    """Change the zone record to the new IP"""

    zone_record = {"name": opts.a_name, "value": new_ip, "ttl": opts.ttl, "type": "A"}

    new_zone_ver = api.domain.zone.version.new(opts.production_key, get_zone_id(opts))

    # clear old A record (defaults to previous verison's
    api.domain.zone.record.delete(
        opts.production_key,
        get_zone_id(opts),
        new_zone_ver,
        {"type": "A", "name": opts.a_name},
    )

    # Add in new A record
    api.domain.zone.record.add(
        opts.production_key, get_zone_id(opts), new_zone_ver, zone_record
    )

    # Set new zone version as the active zone
    api.domain.zone.version.set(opts.production_key, get_zone_id(opts), new_zone_ver)


def main():
    ap = ArgumentParser()
    ap.add_argument("-k", "--production-key", default=None)
    ap.add_argument("-d", "--domain-dame", default=None)
    ap.add_argument("-a", "--a-name", default=None)
    ap.add_argument("-m", "--mode", default="remote", choices=["remote", "local"])
    ap.add_argument("-t", "--ttl", default=300, type=int)
    ap.add_argument("-i", "--ext-ip-server", default="http://ipv4.myexternalip.com/raw")
    ap.add_argument("-l", "--loc-ip-server", default="google.com")
    ap.add_argument("-I", "--interface", default=None)
    ap.add_argument("-p", "--loc-ip-port", default=80, type=int)
    ap.add_argument("-L", "--list-interfaces", action="store_true")
    opts = ap.parse_args()

    if opts.list_interfaces:
        interfaces = get_all_ip_interfaces()
        print("\n".join("{}: {}".format(*e) for e in interfaces.items()))
        return

    if opts.production_key is None:
        msg = "No production key provided"
        raise RuntimeError(msg)

    if opts.domain_dame is None:
        msg = "No domain name provided"
        raise RuntimeError(msg)

    if opts.a_name is None:
        msg = "No A name provided"
        raise RuntimeError(msg)

    zone_ip = get_zone_ip(opts)

    if opts.mode == "remote":
        current_ip = get_remote_ip(opts)
    else:
        current_ip = get_local_ip(opts)

    if zone_ip.strip() == current_ip.strip():
        sys.exit()
    else:
        print(
            "[info] DNS Mistmatch detected: A-record: ",
            zone_ip,
            " WAN IP: ",
            current_ip,
        )
        change_zone_ip(current_ip, opts)
        zone_id = None
        zone_ip = get_zone_ip(opts)
        print("[info] DNS A record update complete - set to ", zone_ip)


if __name__ == "__main__":
    main()
