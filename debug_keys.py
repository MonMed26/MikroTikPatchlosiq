#!/usr/bin/env python3
"""Helper script for key analysis - used by debug-keys workflow"""
import os
import sys

sys.path.insert(0, '.')
from npk import NovaPackage, NpkPartID, NpkFileContainer

LK = bytes.fromhex("8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32")
NK = bytes.fromhex("C293CED638A2A33C681FC8DE98EE26C54EADC5390C2DFCE197D35C83C416CF59")

def check_initrd(npk_file, label):
    print(f"\n=== INITRD: {label} ===")
    npk = NovaPackage.load(npk_file)
    fc = NpkFileContainer.unserialize_from(npk[NpkPartID.FILE_CONTAINER].data)
    for item in fc:
        hl = LK in item.data
        hn = NK in item.data
        tags = []
        if hl: tags.append("LICENSE")
        if hn: tags.append("NPK_SIGN")
        status = ', '.join(tags) if tags else 'no keys'
        print(f"  {item.name}: {len(item.data)} bytes - {status}")

if __name__ == '__main__':
    check_initrd('system17.npk', 'v6.49.17')
    check_initrd('system18.npk', 'v6.49.18')
