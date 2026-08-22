"""Generate diagrams/mechanical.svg from instrument.obj.

Every dimension on the drawing is read from the mesh at generation time, so the
drawing and the model cannot drift apart. Re-run after any model change.

Model axes:  X = length (right +)   Y = height (up +)   Z = depth (front +)
"""
import sys
from pathlib import Path

import numpy as np
from collections import OrderedDict

# Paths are resolved relative to the repo root, so this runs from anywhere:
#     python tools/gen_mechanical.py [model.obj] [out.svg]
ROOT = Path(__file__).resolve().parent.parent
OBJ = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'models' / 'instrument.obj'
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / 'diagrams' / 'mechanical.svg'

# ---- parse -------------------------------------------------------------
if not OBJ.exists():
    raise SystemExit(f"{OBJ} not found.")

# The model is tracked with Git LFS. A checkout without LFS leaves a ~130-byte
# pointer file here, and parsing it yields no vertices — which surfaces much
# later as an unhelpful "zero-size array" from numpy. Say what is actually
# wrong instead.
_head = OBJ.open('rb').read(64)
if _head.startswith(b'version https://git-lfs'):
    raise SystemExit(
        f"{OBJ} is a Git LFS pointer, not the mesh.\n"
        f"  git lfs install && git lfs pull\n"
        f"In CI, set 'lfs: true' on actions/checkout.")

objs = OrderedDict(); cur = None; V = []
for line in open(OBJ):
    if line.startswith('v '):
        V.append([float(x) for x in line.split()[1:4]])
        if cur: objs[cur][1].append(len(V) - 1)
    elif line.startswith('o '):
        cur = line[2:].strip(); objs.setdefault(cur, [None, []])
    elif line.startswith('usemtl') and cur:
        objs[cur][0] = line.split()[1]
V = np.array(V)

def ext(name, *alts):
    """Extent of a named object, trying alternates so a renamed part in the
    model does not silently drop a dimension off the drawing."""
    for n in (name, *alts):
        if n in objs:
            P = V[objs[n][1]]; return P.min(0), P.max(0)
    raise SystemExit(f"{OBJ}: no object named {' / '.join((name, *alts))}. "
                     f"The model was renamed — update tools/gen_mechanical.py.")
def group(pfx):
    idx = [i for k, (_, ii) in objs.items() if k.startswith(pfx) for i in ii]
    P = V[idx]; return P.min(0), P.max(0), P

if len(V) == 0:
    raise SystemExit(f"{OBJ} contains no vertices — is it a complete OBJ export?")
lo, hi = V.min(0), V.max(0)
L, HT, D = hi[0]-lo[0], hi[1]-lo[1], hi[2]-lo[2]

dl, dh = ext('recess_floor_etch')
DISH_C = ((dl[0]+dh[0])/2, (dl[2]+dh[2])/2); DISH_R = (dh[0]-dl[0])/2
DECK_Y = ext('shell_deck')[1][1]; RECESS_Y = dl[1]

rl, rh = ext('ring')
RING_C = ((rl[0]+rh[0])/2, (rl[2]+rh[2])/2)
RING_OD = rh[0]-rl[0]
rp = V[objs['ring'][1]]
rr = np.hypot(rp[:,0]-RING_C[0], rp[:,2]-RING_C[1])
RING_ID = 2*rr[rr > 0.1].min(); RING_H = rh[1]-rl[1]

_,_,tp = group('index_')
TICK_R = np.hypot(tp[:,0]-DISH_C[0], tp[:,2]-DISH_C[1]).mean()
N_TICK = sum(1 for k in objs if k.startswith('index_'))
N_KNURL = sum(1 for k in objs if k.startswith('knurl_'))

gl, gh = ext('display_glass')
pl, ph = ext('pad', 'pad_print')
sl, sh = ext('front_slot')
bl, bh = ext('rear_bay')
ul, uh = ext('usb_c')
sel, seh = ext('parting_seam')
vl, vh, _ = group('vent_')
N_VENT = sum(1 for k in objs if k.startswith('vent_'))

# Discovered from the model, not hardcoded — button positions are named after
# their X coordinate in the source, so pinning the names here means any nudge
# to the layout breaks the drawing instead of updating it. Sorted by X, so the
# CONFIRM button (the large one) stays last where the legend expects it.
BTN = []
for k in sorted((k for k in objs if k.startswith('button_')),
                key=lambda k: ext(k)[0][0]):
    a, b = ext(k)
    BTN.append(((a[0]+b[0])/2, (a[2]+b[2])/2, b[0]-a[0]))
if not BTN:
    raise SystemExit(f"{OBJ}: no button_* objects found.")

FAST = [ext(k) for k in objs if k.startswith('fastener_') and 'slot' not in k]

# ---- svg helpers -------------------------------------------------------
W = 1180          # height is computed from the content, see the notes block
S = 4.15
o = []; A = o.append
INK, DIM, RED, MUT, STEEL = '#D8D2C8', '#8A8B8F', '#B23A48', '#6F7178', '#9FA3A8'

def dim_h(x1, x2, y, txt, col=DIM, off=0):
    A(f'<line x1="{x1:.1f}" y1="{y:.1f}" x2="{x2:.1f}" y2="{y:.1f}" stroke="{col}" stroke-width="0.7"/>')
    for x in (x1, x2):
        A(f'<line x1="{x:.1f}" y1="{y-3:.1f}" x2="{x:.1f}" y2="{y+3:.1f}" stroke="{col}" stroke-width="0.7"/>')
    A(f'<text x="{(x1+x2)/2:.1f}" y="{y-5+off:.1f}" font-size="9.5" text-anchor="middle" fill="{col}">{txt}</text>')

def dim_v(y1, y2, x, txt, col=DIM):
    A(f'<line x1="{x:.1f}" y1="{y1:.1f}" x2="{x:.1f}" y2="{y2:.1f}" stroke="{col}" stroke-width="0.7"/>')
    for y in (y1, y2):
        A(f'<line x1="{x-3:.1f}" y1="{y:.1f}" x2="{x+3:.1f}" y2="{y:.1f}" stroke="{col}" stroke-width="0.7"/>')
    A(f'<text x="{x-5:.1f}" y="{(y1+y2)/2+3:.1f}" font-size="9.5" text-anchor="end" fill="{col}">{txt}</text>')

def lead(x, y, tx, ty, txt, col=MUT, anchor='start'):
    A(f'<path d="M{x:.1f},{y:.1f} L{tx:.1f},{ty:.1f}" stroke="{col}" stroke-width="0.6" fill="none"/>')
    A(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="1.3" fill="{col}"/>')
    dx = 4 if anchor == 'start' else -4
    A(f'<text x="{tx+dx:.1f}" y="{ty+3:.1f}" font-size="9" text-anchor="{anchor}" fill="{col}">{txt}</text>')

# Placeholders. The canvas height is not known until the notes have been laid
# out, and hard-coding it is how the last note ended up clipped off the bottom
# when its text grew. Both are filled in at the end.
A('')   # <svg>
A('')   # background
A(f'<text x="46" y="50" font-size="21" font-weight="200" letter-spacing="9" fill="{INK}">CELL — MECHANICAL</text>')
A(f'<rect x="47" y="61" width="26" height="2" fill="{RED}"/>')
A(f'<text x="46" y="82" font-size="10" letter-spacing="2" fill="{MUT}">Every dimension read from instrument.obj at generation time. Regenerate after any model change. Millimetres.</text>')
A(f'<text x="{W-64}" y="50" text-anchor="end" font-size="10.5" letter-spacing="1.8" fill="{MUT}">{L:.1f} × {D:.1f} × {HT:.1f}</text>')
A(f'<text x="{W-64}" y="68" text-anchor="end" font-size="10.5" letter-spacing="1.8" fill="{MUT}">{len(objs)} objects · {len(V):,} verts</text>')

# ================= TOP =================================================
TX, TY = 128, 138
def tx(x): return TX + (x - lo[0]) * S
def tz(z): return TY + (z - lo[2]) * S

A(f'<text x="46" y="{TY-16:.0f}" font-size="10" letter-spacing="3" fill="{MUT}">TOP</text>')
A(f'<rect x="{tx(lo[0]):.1f}" y="{tz(lo[2]):.1f}" width="{L*S:.1f}" height="{D*S:.1f}" rx="{3*S:.1f}" '
  f'fill="#121211" stroke="{DIM}" stroke-width="0.9"/>')
# dish
A(f'<circle cx="{tx(DISH_C[0]):.1f}" cy="{tz(DISH_C[1]):.1f}" r="{DISH_R*S:.1f}" fill="#171514" stroke="{DIM}" stroke-width="0.8"/>')
A(f'<circle cx="{tx(DISH_C[0]):.1f}" cy="{tz(DISH_C[1]):.1f}" r="{TICK_R*S:.1f}" fill="none" stroke="{RED}" stroke-width="0.5" opacity="0.5" stroke-dasharray="2 3"/>')
for i in range(N_TICK):
    a = 2*np.pi*i/N_TICK
    r0, r1 = TICK_R-1.1, TICK_R+1.1
    c = STEEL if i % 5 == 0 else RED
    A(f'<line x1="{tx(DISH_C[0]+r0*np.cos(a)):.1f}" y1="{tz(DISH_C[1]+r0*np.sin(a)):.1f}" '
      f'x2="{tx(DISH_C[0]+r1*np.cos(a)):.1f}" y2="{tz(DISH_C[1]+r1*np.sin(a)):.1f}" '
      f'stroke="{c}" stroke-width="{1.1 if i%5==0 else 0.7}" opacity="{0.95 if i%5==0 else 0.6}"/>')
A(f'<circle cx="{tx(RING_C[0]):.1f}" cy="{tz(RING_C[1]):.1f}" r="{RING_OD/2*S:.1f}" fill="#2A0C12" stroke="{RED}" stroke-width="1.5"/>')
A(f'<circle cx="{tx(RING_C[0]):.1f}" cy="{tz(RING_C[1]):.1f}" r="{RING_ID/2*S:.1f}" fill="#0C0C0B" stroke="{RED}" stroke-width="0.9"/>')
# display
A(f'<rect x="{tx(gl[0]):.1f}" y="{tz(gl[2]):.1f}" width="{(gh[0]-gl[0])*S:.1f}" height="{(gh[2]-gl[2])*S:.1f}" '
  f'rx="2" fill="#06070A" stroke="{RED}" stroke-width="0.8" opacity="0.95"/>')
# pad (reserved)
A(f'<rect x="{tx(pl[0]):.1f}" y="{tz(pl[2]):.1f}" width="{(ph[0]-pl[0])*S:.1f}" height="{(ph[2]-pl[2])*S:.1f}" '
  f'rx="{2*S:.1f}" fill="none" stroke="{MUT}" stroke-width="0.8" stroke-dasharray="4 3"/>')
# buttons
for i, (bx, bz, bd) in enumerate(BTN):
    c = RED if i == 3 else DIM
    A(f'<circle cx="{tx(bx):.1f}" cy="{tz(bz):.1f}" r="{bd/2*S:.1f}" fill="#0E0F12" stroke="{c}" stroke-width="1.0"/>')
# front slot dashed through top
A(f'<rect x="{tx(sl[0]):.1f}" y="{tz(sl[2]):.1f}" width="{(sh[0]-sl[0])*S:.1f}" height="{(sh[2]-sl[2])*S:.1f}" '
  f'fill="none" stroke="{RED}" stroke-width="0.7" stroke-dasharray="3 2"/>')
A(f'<rect x="{tx(bl[0]):.1f}" y="{tz(bl[2]):.1f}" width="{(bh[0]-bl[0])*S:.1f}" height="{(bh[2]-bl[2])*S:.1f}" '
  f'fill="none" stroke="{MUT}" stroke-width="0.7" stroke-dasharray="3 2"/>')

dim_h(tx(lo[0]), tx(hi[0]), tz(lo[2])-16, f'{L:.1f}')
dim_v(tz(lo[2]), tz(hi[2]), tx(lo[0])-14, f'{D:.1f}')
# Label rows are assigned in order of how high each feature sits in the view,
# so leader lines fan out instead of crossing. Ordering them by hand is what
# put the rear-bay leader — anchored at the very back — on the bottom row,
# raking its line across every other leader on the way there.
top_leads = sorted([
    (tx(DISH_C[0])+DISH_R*S*0.72, tz(DISH_C[1])-DISH_R*S*0.72,
     f'dish Ø{DISH_R*2:.1f} × {DECK_Y-RECESS_Y:.1f} deep'),
    (tx(RING_C[0])+RING_OD/2*S, tz(RING_C[1]),
     f'ring Ø{RING_OD:.1f}/Ø{RING_ID:.1f}, {RING_H:.1f} proud'),
    (tx(DISH_C[0]), tz(DISH_C[1]-TICK_R),
     f'{N_TICK} ticks @ R{TICK_R:.1f}, every 5th steel'),
    (tx(sh[0]), tz((sl[2]+sh[2])/2),
     f'sample slot {sh[0]-sl[0]:.1f} × {sh[1]-sl[1]:.1f}, front'),
    (tx(bh[0]), tz((bl[2]+bh[2])/2),
     f'compute bay {bh[0]-bl[0]:.0f} × {bh[1]-bl[1]:.0f}, rear'),
], key=lambda t: t[1])
for i, (ax, ay, txt) in enumerate(top_leads):
    lead(ax, ay, tx(hi[0])+34, tz(lo[2])+16 + 24*i, txt)
# left-half features get a legend row instead of leaders that would cross the dish
LGY = tz(hi[2]) + 26
A(f'<text x="{tx(lo[0]):.1f}" y="{LGY:.0f}" font-size="9.5" fill="{MUT}">'
  f'display {gh[0]-gl[0]:.1f} × {gh[2]-gl[2]:.1f}'
  f'  ·  buttons Ø{BTN[0][2]:.1f}, <tspan fill="{RED}">CONFIRM Ø{BTN[3][2]:.1f}</tspan>'
  f'  ·  pad {ph[0]-pl[0]:.1f} × {ph[2]-pl[2]:.1f} <tspan fill="{MUT}">(reserved, print flat)</tspan></text>')

# ================= FRONT ===============================================
FY = TY + D*S + 118
def fy(y): return FY + (hi[1] - y) * S
A(f'<text x="46" y="{FY-16:.0f}" font-size="10" letter-spacing="3" fill="{MUT}">FRONT</text>')
A(f'<rect x="{tx(lo[0]):.1f}" y="{fy(hi[1]):.1f}" width="{L*S:.1f}" height="{HT*S:.1f}" rx="{3*S:.1f}" '
  f'fill="#121211" stroke="{DIM}" stroke-width="0.9"/>')
A(f'<rect x="{tx(lo[0]):.1f}" y="{fy(seh[1]):.1f}" width="{L*S:.1f}" height="{(seh[1]-sel[1])*S:.1f}" fill="{RED}" opacity="0.85"/>')
A(f'<rect x="{tx(sl[0]):.1f}" y="{fy(sh[1]):.1f}" width="{(sh[0]-sl[0])*S:.1f}" height="{(sh[1]-sl[1])*S:.1f}" '
  f'fill="#000" stroke="{RED}" stroke-width="0.9"/>')
for i in range(N_VENT):
    vx = vl[0] + (vh[0]-vl[0]) * (i + 0.22) / N_VENT
    A(f'<rect x="{tx(vx):.1f}" y="{fy(vh[1]):.1f}" width="{0.6*S:.1f}" height="{(vh[1]-vl[1])*S:.1f}" fill="#08080A" stroke="{MUT}" stroke-width="0.3"/>')
for a, b in FAST:
    A(f'<circle cx="{tx((a[0]+b[0])/2):.1f}" cy="{fy((a[1]+b[1])/2):.1f}" r="{(b[0]-a[0])/2*S:.1f}" fill="#16171A" stroke="{STEEL}" stroke-width="0.8"/>')
    A(f'<line x1="{tx((a[0]+b[0])/2)-(b[0]-a[0])/2.7*S:.1f}" y1="{fy((a[1]+b[1])/2):.1f}" '
      f'x2="{tx((a[0]+b[0])/2)+(b[0]-a[0])/2.7*S:.1f}" y2="{fy((a[1]+b[1])/2):.1f}" stroke="{STEEL}" stroke-width="1.0"/>')
dim_v(fy(hi[1]), fy(lo[1]), tx(lo[0])-14, f'{HT:.1f}')
lead(tx(sh[0]), fy((sl[1]+sh[1])/2), tx(hi[0])+34, fy(hi[1])+16, f'sample slot {sh[0]-sl[0]:.1f} × {sh[1]-sl[1]:.1f}')
lead(tx(vh[0]), fy((vl[1]+vh[1])/2), tx(hi[0])+34, fy(hi[1])+40, f'{N_VENT} vents — MUST BE BLIND')
lead(tx(hi[0])-6, fy(seh[1]), tx(hi[0])+34, fy(hi[1])+64, f'parting seam @ {seh[1]:.1f} from base')
lead(tx(FAST[1][1][0]), fy((FAST[1][0][1]+FAST[1][1][1])/2), tx(hi[0])+34, fy(hi[1])+88, 'slotted fastener ×2')

# ================= REAR + RIGHT ========================================
RY = FY + HT*S + 96
A(f'<text x="46" y="{RY-16:.0f}" font-size="10" letter-spacing="3" fill="{MUT}">REAR</text>')
A(f'<rect x="{tx(lo[0]):.1f}" y="{RY:.1f}" width="{L*S:.1f}" height="{HT*S:.1f}" rx="{3*S:.1f}" fill="#121211" stroke="{DIM}" stroke-width="0.9"/>')
A(f'<rect x="{tx(lo[0]):.1f}" y="{RY+(hi[1]-seh[1])*S:.1f}" width="{L*S:.1f}" height="{(seh[1]-sel[1])*S:.1f}" fill="{RED}" opacity="0.85"/>')
A(f'<rect x="{tx(-bh[0]):.1f}" y="{RY+(hi[1]-bh[1])*S:.1f}" width="{(bh[0]-bl[0])*S:.1f}" height="{(bh[1]-bl[1])*S:.1f}" '
  f'fill="#0A140E" stroke="#2E7D5B" stroke-width="1.0"/>')
A(f'<text x="{tx(0):.1f}" y="{RY+(hi[1]-(bl[1]+bh[1])/2)*S+4:.1f}" font-size="10" text-anchor="middle" fill="#8FB8A2">Pi Zero 2 W bay — {bh[0]-bl[0]:.0f} × {bh[1]-bl[1]:.0f} × {bh[2]-bl[2]:.1f}</text>')

RX2 = tx(hi[0]) + 96
def rx(z): return RX2 + (hi[2] - z) * S
A(f'<text x="{RX2:.0f}" y="{RY-16:.0f}" font-size="10" letter-spacing="3" fill="{MUT}">RIGHT   (front →)</text>')
A(f'<rect x="{rx(hi[2]):.1f}" y="{RY:.1f}" width="{D*S:.1f}" height="{HT*S:.1f}" rx="{3*S:.1f}" fill="#121211" stroke="{DIM}" stroke-width="0.9"/>')
A(f'<rect x="{rx(hi[2]):.1f}" y="{RY+(hi[1]-seh[1])*S:.1f}" width="{D*S:.1f}" height="{(seh[1]-sel[1])*S:.1f}" fill="{RED}" opacity="0.85"/>')
A(f'<rect x="{rx(uh[2]):.1f}" y="{RY+(hi[1]-uh[1])*S:.1f}" width="{(uh[2]-ul[2])*S:.1f}" height="{(uh[1]-ul[1])*S:.1f}" '
  f'rx="{1.6*S:.1f}" fill="#000" stroke="{STEEL}" stroke-width="0.9"/>')
A(f'<text x="{rx((ul[2]+uh[2])/2):.1f}" y="{RY+HT*S+16:.1f}" font-size="9" text-anchor="middle" fill="{MUT}">USB-C {uh[2]-ul[2]:.1f} × {uh[1]-ul[1]:.1f} — power only</text>')
dim_h(rx(hi[2]), rx(lo[2]), RY-4, f'{D:.1f}')

# ================= NOTES ===============================================
NY = RY + HT*S + 56
A(f'<line x1="46" y1="{NY-18:.0f}" x2="{W-46}" y2="{NY-18:.0f}" stroke="#22242A" stroke-width="1"/>')
A(f'<text x="46" y="{NY:.0f}" font-size="10" letter-spacing="3" fill="{MUT}">THREE THINGS THE MODEL DOES NOT SAY</text>')
notes = [
    ('Vents must be blind pockets.', f'{N_VENT} slots on the front face, {vh[2]-vl[2]:.1f} deep. If any becomes a through-hole, ambient light reaches the optical chamber and the 415 nm gate fails. Print them blind and verify with the light-tightness test.'),
    ('The pad is reserved, not fitted.', f'{ph[0]-pl[0]:.1f} × {ph[2]-pl[2]:.1f} printed marking sizing the optional fingerprint sensor. Deliberately flat, not a pocket: an unpopulated recess on the deck collects blood. The base build leaves it blank — the PIN does identity.'),
    ('The dish is the reader, not a dial.', 'The ring is a bezel, not a control. Nothing rotates. The cartridge enters through the front slot and sits under the dish.'),
]
# Wrap to the full page width, and let each note take the height it needs.
# The previous fixed 44 px pitch silently assumed every body fitted in two
# lines; a longer one overran the note below it and then the canvas.
WRAP = int((W - 92) / 5.05)      # ~5.05 px per char at font-size 9.5
y = NY + 24
for h, b in notes:
    A(f'<text x="46" y="{y:.0f}" font-size="11" fill="{INK}">{h}</text>')
    lines = ['']
    for w in b.split():
        if len(lines[-1]) + len(w) > WRAP:
            lines.append('')
        lines[-1] += w + ' '
    for j, ln in enumerate(lines):
        A(f'<text x="46" y="{y+16+j*14:.0f}" font-size="9.5" fill="{MUT}">{ln.strip()}</text>')
    y += 16 + len(lines)*14 + 16

H = int(y + 20)
o[0] = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
        f'width="{W}" height="{H}" '
        f'font-family="Helvetica Neue, Helvetica, Arial, sans-serif">')
o[1] = f'<rect width="{W}" height="{H}" fill="#0C0C0B"/>'

A('</svg>')
OUT.write_text('\n'.join(o))
print(f'wrote {OUT}  ({len(objs)} objects, {len(V):,} verts)')
print(f"wrote {OUT}")
print(f"  envelope        {L:.2f} × {D:.2f} × {HT:.2f}")
print(f"  dish            Ø{DISH_R*2:.2f}, {DECK_Y-RECESS_Y:.2f} deep")
print(f"  ring            Ø{RING_OD:.2f} OD / Ø{RING_ID:.2f} ID, {RING_H:.2f} proud"
      + (f", {N_KNURL} knurls" if N_KNURL else " (smooth bezel)"))
print(f"  ticks           {N_TICK} @ R{TICK_R:.2f}")
print(f"  display         {gh[0]-gl[0]:.2f} × {gh[2]-gl[2]:.2f}")
print(f"  pad             {ph[0]-pl[0]:.2f} × {ph[2]-pl[2]:.2f}")
print(f"  front slot      {sh[0]-sl[0]:.2f} × {sh[1]-sl[1]:.2f} × {sh[2]-sl[2]:.2f} deep")
print(f"  rear bay        {bh[0]-bl[0]:.2f} × {bh[1]-bl[1]:.2f} × {bh[2]-bl[2]:.2f} deep")
print(f"  usb-c           {uh[2]-ul[2]:.2f} × {uh[1]-ul[1]:.2f}")
print(f"  seam            {seh[1]:.2f} from base")
print(f"  buttons         " + ", ".join(f"Ø{b[2]:.1f}" for b in BTN))
