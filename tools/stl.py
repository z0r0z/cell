"""Minimal mesh construction and binary-STL output. Pure stdlib, no deps.

Two meshers live here:

  * analytic builders (`slab_with_pocket`, `box`, `tube`) for parts whose
    features are axis-aligned prisms and coaxial cylinders — exact geometry,
    no facet error beyond the circle tessellation you ask for;
  * `sdf_mesh`, a naive surface-nets isosurface mesher, for parts that need
    real CSG (bores entering a wall at 30 or 45 degrees). Its accuracy is the
    grid pitch, so it is used only where a tenth of a millimetre on a
    clearance bore does not matter.

Units are millimetres throughout. Triangles are (v0, v1, v2) with outward
normals by right-hand rule.
"""

import math
import struct

TAU = math.pi * 2


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

def write_stl(path, tris, header=b"cell"):
    with open(path, "wb") as fh:
        fh.write(header[:80].ljust(80, b"\0"))
        fh.write(struct.pack("<I", len(tris)))
        for a, b, c in tris:
            ux, uy, uz = b[0] - a[0], b[1] - a[1], b[2] - a[2]
            vx, vy, vz = c[0] - a[0], c[1] - a[1], c[2] - a[2]
            nx, ny, nz = uy * vz - uz * vy, uz * vx - ux * vz, ux * vy - uy * vx
            n = math.sqrt(nx * nx + ny * ny + nz * nz) or 1.0
            fh.write(struct.pack("<12fH", nx / n, ny / n, nz / n,
                                 *a, *b, *c, 0))
    return len(tris)


def snap(tris, places=6):
    """Round vertices onto a common grid and drop degenerates.

    Circles evaluated at theta=0 and theta=2*pi differ in the last bit, which
    leaves a hairline seam that reads as a hole to a slicer. Rounding closes it.
    """
    out = []
    for tri in tris:
        t = tuple(tuple(round(v, places) + 0.0 for v in p) for p in tri)
        if len(set(t)) == 3 and _area2(t) > 1e-18:
            out.append(t)
    return out


def quad(a, b, c, d):
    """Two triangles for a planar quad wound a-b-c-d."""
    return [(a, b, c), (a, c, d)]


# --------------------------------------------------------------------------
# analytic primitives
# --------------------------------------------------------------------------

def box(x0, y0, z0, x1, y1, z1):
    t = []
    t += quad((x0, y0, z0), (x0, y1, z0), (x1, y1, z0), (x1, y0, z0))      # -Z
    t += quad((x0, y0, z1), (x1, y0, z1), (x1, y1, z1), (x0, y1, z1))      # +Z
    t += quad((x0, y0, z0), (x1, y0, z0), (x1, y0, z1), (x0, y0, z1))      # -Y
    t += quad((x1, y0, z0), (x1, y1, z0), (x1, y1, z1), (x1, y0, z1))      # +X
    t += quad((x1, y1, z0), (x0, y1, z0), (x0, y1, z1), (x1, y1, z1))      # +Y
    t += quad((x0, y1, z0), (x0, y0, z0), (x0, y0, z1), (x0, y1, z1))      # -X
    return t


def lathe(profile, n=96, cx=0.0, cy=0.0):
    """Surface of revolution about Z from a closed (r, z) profile.

    The profile is traversed so that material lies to its left in the r-z
    half-plane; that convention makes every generated facet point outward.
    """
    m = len(profile)
    tris = []
    for i in range(m):
        r0, z0 = profile[i]
        r1, z1 = profile[(i + 1) % m]
        for k in range(n):
            a0 = TAU * k / n
            a1 = TAU * (k + 1) / n
            p00 = (cx + r0 * math.cos(a0), cy + r0 * math.sin(a0), z0)
            p01 = (cx + r0 * math.cos(a1), cy + r0 * math.sin(a1), z0)
            p10 = (cx + r1 * math.cos(a0), cy + r1 * math.sin(a0), z1)
            p11 = (cx + r1 * math.cos(a1), cy + r1 * math.sin(a1), z1)
            tris += quad(p00, p10, p11, p01)
    return [t for t in tris if _area2(t) > 1e-18]


def _area2(t):
    (ax, ay, az), (bx, by, bz), (cx_, cy_, cz) = t
    ux, uy, uz = bx - ax, by - ay, bz - az
    vx, vy, vz = cx_ - ax, cy_ - ay, cz - az
    nx, ny, nz = uy * vz - uz * vy, uz * vx - ux * vz, ux * vy - uy * vx
    return nx * nx + ny * ny + nz * nz


def tube(cx, cy, z0, z1, r_out, r_in, n=96, flange_r=None, flange_h=0.0):
    """Hollow cylinder, optionally with a seating flange at the z0 end.

    One lathed shell -- no stacked solids, so no doubled faces where a flange
    meets the barrel.
    """
    if flange_r:
        prof = [(r_in, z0), (flange_r, z0), (flange_r, z0 + flange_h),
                (r_out, z0 + flange_h), (r_out, z1), (r_in, z1)]
    else:
        prof = [(r_in, z0), (r_out, z0), (r_out, z1), (r_in, z1)]
    return snap(lathe(prof[::-1], n, cx, cy))


def _rect_ray(cx, cy, x0, y0, x1, y1, theta):
    """Where the ray from (cx,cy) at `theta` leaves the rectangle."""
    dx, dy = math.cos(theta), math.sin(theta)
    ts = []
    if abs(dx) > 1e-12:
        ts.append(((x1 if dx > 0 else x0) - cx) / dx)
    if abs(dy) > 1e-12:
        ts.append(((y1 if dy > 0 else y0) - cy) / dy)
    s = min(ts)
    return (cx + dx * s, cy + dy * s)


def slab_with_pocket(x0, y0, x1, y1, t, pocket=None, n=192):
    """Rectangular slab from z=0 to z=t, optionally holding one concentric
    two-step pocket -- a well inside a shallower overflow moat, so overflow
    crosses the well lip instead of reaching the moat outer wall.

    pocket = dict(cx, cy, r_well, d_well, r_moat, d_moat), or None.
    """
    if pocket is None:
        return snap(box(x0, y0, 0, x1, y1, t))

    cx, cy = pocket["cx"], pocket["cy"]
    rw, dw = pocket["r_well"], pocket["d_well"]
    rm, dm = pocket["r_moat"], pocket["d_moat"]

    # One perimeter polygon serves the top face, the side walls and the base,
    # so all three agree edge for edge. The rectangle's own corners are added
    # to the sample angles, otherwise the polygon cuts them off.
    angles = [TAU * i / n for i in range(n)]
    for corner in ((x0, y0), (x1, y0), (x1, y1), (x0, y1)):
        angles.append(math.atan2(corner[1] - cy, corner[0] - cx) % TAU)
    angles = sorted(set(angles))
    m = len(angles)

    per = [_rect_ray(cx, cy, x0, y0, x1, y1, a) for a in angles]
    rim = [(cx + rm * math.cos(a), cy + rm * math.sin(a), t) for a in angles]

    tris = []
    for i in range(m):                                   # top face, holed
        j = (i + 1) % m
        tris += quad(per[i] + (t,), per[j] + (t,), rim[j], rim[i])
    for i in range(m):                                   # side walls
        j = (i + 1) % m
        tris += quad(per[i] + (0.0,), per[j] + (0.0,),
                     per[j] + (t,), per[i] + (t,))
    base = (cx, cy, 0.0)                                 # base, fanned
    for i in range(m):
        j = (i + 1) % m
        tris.append((base, per[j] + (0.0,), per[i] + (0.0,)))

    # pocket walls and floors, one inward-facing surface of revolution
    prof = [(rm, t), (rm, t - dm), (rw, t - dm), (rw, t - dw), (0.0, t - dw)]
    for i in range(len(prof) - 1):
        r0, z0 = prof[i]
        r1, z1 = prof[i + 1]
        for k in range(m):
            a0, a1 = angles[k], angles[(k + 1) % m] + (TAU if k == m - 1 else 0)
            p00 = (cx + r0 * math.cos(a0), cy + r0 * math.sin(a0), z0)
            p01 = (cx + r0 * math.cos(a1), cy + r0 * math.sin(a1), z0)
            p10 = (cx + r1 * math.cos(a0), cy + r1 * math.sin(a0), z1)
            p11 = (cx + r1 * math.cos(a1), cy + r1 * math.sin(a1), z1)
            tris += quad(p00, p01, p11, p10)
    return snap(tris)


# --------------------------------------------------------------------------
# SDF helpers + naive surface nets
# --------------------------------------------------------------------------

def sd_box(p, c, h):
    d = [abs(p[i] - c[i]) - h[i] for i in range(3)]
    out = math.sqrt(sum(max(v, 0.0) ** 2 for v in d))
    return out + min(max(d[0], max(d[1], d[2])), 0.0)


def sd_capsule_axis(p, a, b, r):
    """Distance to a finite cylinder of radius r with hemispherical caps.

    Used for bores: the caps sit outside the solid, so the cut is a clean
    through-hole.
    """
    pa = [p[i] - a[i] for i in range(3)]
    ba = [b[i] - a[i] for i in range(3)]
    bb = sum(v * v for v in ba) or 1e-12
    h = max(0.0, min(1.0, sum(pa[i] * ba[i] for i in range(3)) / bb))
    d = [pa[i] - ba[i] * h for i in range(3)]
    return math.sqrt(sum(v * v for v in d)) - r


def sd_cyl_axis(p, a, b, r):
    """Flat-capped finite cylinder."""
    ba = [b[i] - a[i] for i in range(3)]
    L = math.sqrt(sum(v * v for v in ba))
    ba = [v / L for v in ba]
    pa = [p[i] - a[i] for i in range(3)]
    t = sum(pa[i] * ba[i] for i in range(3))
    radial = math.sqrt(max(0.0, sum(v * v for v in pa) - t * t)) - r
    axial = abs(t - L / 2) - L / 2
    if radial <= 0 and axial <= 0:
        return max(radial, axial)
    return math.sqrt(max(radial, 0) ** 2 + max(axial, 0) ** 2)


def sdf_mesh(f, bounds, pitch):
    """Surface nets over f<0. Returns triangles.

    One dual vertex per sign-changing cell, placed at the mean of its edge
    crossings; each sign-changing grid edge emits the quad of the four cells
    around it. Manifold by construction.
    """
    (bx0, by0, bz0), (bx1, by1, bz1) = bounds
    # Nudge the lattice off round numbers. A sample landing exactly on a flat
    # face gives f == 0, which counts as outside and pinches the surface into a
    # non-manifold edge; no real geometry sits at an irrational offset.
    bx0 -= pitch * 0.1373
    by0 -= pitch * 0.0917
    bz0 -= pitch * 0.0531
    nx = int(math.ceil((bx1 - bx0) / pitch)) + 1
    ny = int(math.ceil((by1 - by0) / pitch)) + 1
    nz = int(math.ceil((bz1 - bz0) / pitch)) + 1

    def pos(i, j, k):
        return (bx0 + i * pitch, by0 + j * pitch, bz0 + k * pitch)

    grid = [f(pos(i, j, k))
            for i in range(nx) for j in range(ny) for k in range(nz)]

    def val(i, j, k):
        return grid[(i * ny + j) * nz + k]

    corners = [(dx, dy, dz) for dx in (0, 1) for dy in (0, 1) for dz in (0, 1)]
    edges = [(0, 1), (0, 2), (0, 4), (1, 3), (1, 5), (2, 3),
             (2, 6), (3, 7), (4, 5), (4, 6), (5, 7), (6, 7)]

    verts = {}
    for i in range(nx - 1):
        for j in range(ny - 1):
            for k in range(nz - 1):
                cv = [val(i + dx, j + dy, k + dz) for dx, dy, dz in corners]
                if min(cv) >= 0 or max(cv) < 0:
                    continue
                acc, cnt = [0.0, 0.0, 0.0], 0
                for a, b in edges:
                    va, vb = cv[a], cv[b]
                    if (va < 0) == (vb < 0):
                        continue
                    s = va / (va - vb)
                    pa = pos(i + corners[a][0], j + corners[a][1], k + corners[a][2])
                    pb = pos(i + corners[b][0], j + corners[b][1], k + corners[b][2])
                    for m in range(3):
                        acc[m] += pa[m] + (pb[m] - pa[m]) * s
                    cnt += 1
                verts[(i, j, k)] = tuple(a / cnt for a in acc)

    tris = []

    def emit(cells, flip):
        try:
            p = [verts[c] for c in cells]
        except KeyError:
            return
        a, b, c, d = p[::-1] if not flip else p
        tris.extend(quad(a, b, c, d))

    for i in range(nx - 1):
        for j in range(1, ny - 1):
            for k in range(1, nz - 1):
                if (val(i, j, k) < 0) != (val(i + 1, j, k) < 0):
                    emit([(i, j - 1, k - 1), (i, j, k - 1), (i, j, k), (i, j - 1, k)],
                         val(i, j, k) < 0)
    for i in range(1, nx - 1):
        for j in range(ny - 1):
            for k in range(1, nz - 1):
                if (val(i, j, k) < 0) != (val(i, j + 1, k) < 0):
                    emit([(i - 1, j, k - 1), (i, j, k - 1), (i, j, k), (i - 1, j, k)],
                         val(i, j, k) >= 0)
    for i in range(1, nx - 1):
        for j in range(1, ny - 1):
            for k in range(nz - 1):
                if (val(i, j, k) < 0) != (val(i, j, k + 1) < 0):
                    emit([(i - 1, j - 1, k), (i, j - 1, k), (i, j, k), (i - 1, j, k)],
                         val(i, j, k) < 0)
    return tris
