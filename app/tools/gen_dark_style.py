#!/usr/bin/env python3
"""Recolors OpenFreeMap's `liberty` style into a Google-Maps-like dark style (night palette).
Usage: gen_dark_style.py [liberty.json] > android/app/src/main/assets/map_style_dark.json
Without an argument the style is downloaded from tiles.openfreemap.org."""
import json, sys, urllib.request

src = open(sys.argv[1]).read() if len(sys.argv) > 1 else urllib.request.urlopen("https://tiles.openfreemap.org/styles/liberty").read().decode()
style = json.loads(src)

BG, WATER, PARK, BUILDING = "#242f3e", "#17263c", "#263c3f", "#2f3948"
ROAD, ROAD_CASE, HWY, HWY_CASE, RAIL = "#38414e", "#212a37", "#746855", "#1f2835", "#3c4658"
PLACE, MUTED, ROAD_TEXT, WATER_TEXT = "#d59563", "#b8bcc6", "#9ca5b3", "#515c6d"

def paint(l, **kw):
    l.setdefault("paint", {}).update(kw)

layers = []
for l in style["layers"]:
    i, t, sl = l["id"], l["type"], l.get("source-layer", "")
    if t == "raster" or "shield" in i:
        continue                                   # natural_earth is a bright low-zoom raster; the shield icons are bright boxes
    if t == "background":
        paint(l, **{"background-color": BG})
    elif t == "fill-extrusion":
        paint(l, **{"fill-extrusion-color": BUILDING, "fill-extrusion-opacity": 0.6})
    elif t == "fill":
        if sl == "water": color = WATER
        elif sl == "building": color = BUILDING
        elif i in ("park", "landcover_wood", "landcover_grass", "landcover_wetland", "landuse_pitch", "landuse_track", "landuse_cemetery"): color = PARK
        elif i in ("landuse_hospital", "landuse_school", "aeroway_fill", "road_area_pattern"): color = BUILDING
        else: color = "#2b3544"
        paint(l, **{"fill-color": color, "fill-opacity": 1})
        l["paint"].pop("fill-outline-color", None)
        l["paint"].pop("fill-pattern", None)
    elif t == "line":
        if sl == "waterway": paint(l, **{"line-color": WATER})
        elif sl == "boundary": paint(l, **{"line-color": "#4b6878"})
        elif i == "park_outline": paint(l, **{"line-color": PARK})
        elif "rail" in i or "transit" in i: paint(l, **{"line-color": RAIL})
        elif i.startswith("aeroway") or i == "aeroway_runway": paint(l, **{"line-color": RAIL})
        else:
            major = "motorway" in i or "trunk_primary" in i
            if "casing" in i: paint(l, **{"line-color": HWY_CASE if major else ROAD_CASE})
            else: paint(l, **{"line-color": HWY if major else ROAD})
    elif t == "symbol":
        p = l.setdefault("paint", {})
        if i.startswith("label_") or i == "airport" or i.startswith("poi"):
            color = MUTED if i.startswith(("label_country", "label_state")) else PLACE
            p.update({"text-color": color, "text-halo-color": BG, "icon-opacity": 0.75})
        elif i.startswith("water") or i == "waterway_line_label":
            p.update({"text-color": WATER_TEXT, "text-halo-color": WATER})
        elif i.startswith(("highway-name", "highway-shield", "road_shield")):
            p.update({"text-color": ROAD_TEXT, "text-halo-color": HWY_CASE, "icon-opacity": 0.6})
        else:                                       # one-way arrows
            p.update({"icon-opacity": 0.35})
    layers.append(l)
style["layers"] = layers
style["name"] = "osfind-dark"
json.dump(style, sys.stdout, separators=(",", ":"))
