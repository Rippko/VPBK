#!/usr/bin/env python3

import oqs
import inspect

print("Dostupné třídy v modulu oqs:")
for name, obj in inspect.getmembers(oqs):
    if inspect.isclass(obj):
        print(f"- Třída: {name}")
        for method_name, method in inspect.getmembers(obj):
            if inspect.isfunction(method) or inspect.ismethod(method):
                print(f"  - Metoda: {method_name}")

# Pokud existuje třída KEM, zkusme vypsat její statické metody
if hasattr(oqs, 'KEM'):
    print("\nDostupné metody třídy KEM:")
    for name, method in inspect.getmembers(oqs.KEM):
        print(f"- {name}")

# Pokud existuje třída Signature, zkusme vypsat její statické metody
if hasattr(oqs, 'Signature'):
    print("\nDostupné metody třídy Signature:")
    for name, method in inspect.getmembers(oqs.Signature):
        print(f"- {name}")

print("\nDostupné algoritmy pro výměnu klíčů:")
for kem_alg in oqs.get_enabled_kem_mechanisms():
    print("-", kem_alg)

print("\nDostupné algoritmy pro digitální podpis:")
for sig_alg in oqs.get_enabled_sig_mechanisms():
    print("-", sig_alg)