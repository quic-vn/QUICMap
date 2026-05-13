APNIC delegated data and the world responsive IPv6 hitlist are used to build per-country input files.

Default files:

- `apnic/delegated-apnic-extended-latest`
- `hitlist-world-responsive-addresses.txt.xz`

Build all APNIC countries:

```bash
cd ..
python3 build_country_hitlists.py
```

Build selected countries:

```bash
cd ..
python3 build_country_hitlists.py --countries VN,TH,SG,ID,MY,PH,KH,LA,MM,BN,TL
```

Outputs:

- Hitlists: `input/<country>_ipv6.txt`
- Prefixes: `database/apnic/<country>_prefix.txt`
