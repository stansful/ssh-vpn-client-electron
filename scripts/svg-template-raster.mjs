// Minimal, dependency-free SVG rasterizer for the monochrome macOS menu-bar template (trayTemplate.svg).
// Supported: <svg viewBox>, <g>, <path>, <circle>, <ellipse>, <rect rx ry>, <line>, <polyline>, <polygon>;
// fill / stroke / stroke-width / fill-rule / stroke-linecap (round|butt|square) / opacity / fill-opacity /
// stroke-opacity / transform / style="...". Joins are always round (miter/bevel are approximated as round).
// Paint semantics (template icons carry shape only): white paint (#fff, #ffffff, white) ERASES what is
// below it in document order; any other colour paints opaque black. Masks, clip paths, gradients, text,
// <use>, filters are rejected so the source never renders differently than intended.

const IGNORED = new Set(["title", "desc", "metadata"]);
const CONTAINERS = new Set(["svg", "g"]);
const SHAPES = new Set(["path", "circle", "ellipse", "rect", "line", "polyline", "polygon"]);
const INHERITED = [
  "fill",
  "stroke",
  "stroke-width",
  "fill-rule",
  "stroke-linecap",
  "stroke-linejoin",
  "fill-opacity",
  "stroke-opacity"
];
const IDENTITY = [1, 0, 0, 1, 0, 0];

function parseSvg(text) {
  const source = text
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<\?[\s\S]*?\?>/g, "")
    .replace(/<!DOCTYPE[^>]*>/gi, "");
  const tagPattern = /<(\/?)([A-Za-z][\w:.-]*)([^>]*?)(\/?)>/g;
  const root = { name: "#root", attrs: {}, children: [] };
  const stack = [root];
  let skipDepth = 0;
  let match;
  while ((match = tagPattern.exec(source))) {
    const [, closing, name, rawAttrs, selfClosing] = match;
    if (closing) {
      if (skipDepth > 0) {
        skipDepth -= 1;
      } else if (stack.length > 1) {
        stack.pop();
      }
      continue;
    }
    if (skipDepth > 0) {
      if (!selfClosing) skipDepth += 1;
      continue;
    }
    if (IGNORED.has(name)) {
      if (!selfClosing) skipDepth = 1;
      continue;
    }
    if (!CONTAINERS.has(name) && !SHAPES.has(name)) {
      throw new Error(
        `Unsupported element <${name}>. Use only svg/g/path/circle/ellipse/rect/line/polyline/polygon; ` +
          `cut holes with fill-rule="evenodd" or white (#fff) erase paint instead of masks/clip paths.`
      );
    }
    const node = { name, attrs: parseAttributes(rawAttrs), children: [] };
    stack.at(-1).children.push(node);
    if (!selfClosing) stack.push(node);
  }
  const svg = root.children.find((node) => node.name === "svg");
  if (!svg) throw new Error("No <svg> root element.");
  return svg;
}

function parseAttributes(raw) {
  const attrs = {};
  const pattern = /([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let match;
  while ((match = pattern.exec(raw))) {
    attrs[match[1]] = match[2] ?? match[3];
  }
  if (attrs.style) {
    for (const declaration of attrs.style.split(";")) {
      const index = declaration.indexOf(":");
      if (index > 0) attrs[declaration.slice(0, index).trim()] = declaration.slice(index + 1).trim();
    }
    delete attrs.style;
  }
  for (const forbidden of ["mask", "clip-path", "filter"]) {
    if (attrs[forbidden] && attrs[forbidden] !== "none") {
      throw new Error(`Unsupported attribute ${forbidden}="${attrs[forbidden]}".`);
    }
  }
  return attrs;
}

function viewBoxOf(svg) {
  const box = svg.attrs.viewBox?.trim().split(/[\s,]+/).map(Number);
  if (box && box.length === 4 && box.every(Number.isFinite)) {
    return { x: box[0], y: box[1], width: box[2], height: box[3] };
  }
  const width = Number.parseFloat(svg.attrs.width);
  const height = Number.parseFloat(svg.attrs.height);
  if (width > 0 && height > 0) return { x: 0, y: 0, width, height };
  throw new Error("The <svg> root needs a viewBox.");
}

/** Collects drawable shapes in pixel space for an output `pixelWidth` wide. */
function collectShapes(svg, pixelWidth) {
  const box = viewBoxOf(svg);
  const scale = pixelWidth / box.width;
  const rootMatrix = multiply([scale, 0, 0, scale, 0, 0], [1, 0, 0, 1, -box.x, -box.y]);
  const shapes = [];
  const walk = (node, inherited, matrix) => {
    const attrs = node.attrs;
    if (attrs.display === "none" || attrs.visibility === "hidden") return;
    const style = { ...inherited };
    for (const key of INHERITED) {
      if (attrs[key] !== undefined && attrs[key] !== "inherit") style[key] = attrs[key];
    }
    const local = attrs.transform ? multiply(matrix, parseTransform(attrs.transform)) : matrix;
    if (CONTAINERS.has(node.name)) {
      if (node.name === "g" && attrs.opacity !== undefined && Number(attrs.opacity) !== 1) {
        throw new Error("Group opacity is not supported; set opacity on the shapes themselves.");
      }
      for (const child of node.children) walk(child, style, local);
      return;
    }
    const subpaths = geometryOf(node).map((subpath) => ({
      ...subpath,
      points: dedupe(subpath.points.map((point) => apply(local, point)))
    }));
    const opacity = number(attrs.opacity, 1);
    const fill = paintOf(style.fill ?? "#000", opacity * number(style["fill-opacity"], 1));
    const strokePaint = paintOf(style.stroke ?? "none", opacity * number(style["stroke-opacity"], 1));
    const strokeWidth = number(style["stroke-width"], 1);
    const determinant = Math.abs(local[0] * local[3] - local[1] * local[2]);
    const shape = {
      subpaths,
      fill: fill && node.name !== "line" ? { ...fill, rule: style["fill-rule"] === "evenodd" ? "evenodd" : "nonzero" } : null,
      stroke:
        strokePaint && strokeWidth > 0
          ? { ...strokePaint, halfWidth: (strokeWidth * Math.sqrt(determinant)) / 2, cap: style["stroke-linecap"] ?? "butt" }
          : null
    };
    if (!shape.fill && !shape.stroke) return;
    shape.bounds = boundsOf(shape);
    shapes.push(shape);
  };
  walk(svg, {}, rootMatrix);
  return { shapes, width: Math.round(box.width * scale), height: Math.round(box.height * scale) };
}

function number(value, fallback) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function paintOf(value, opacity) {
  const paint = String(value).trim().toLowerCase();
  if (paint === "none" || paint === "transparent") return null;
  if (paint.startsWith("url(")) throw new Error(`Gradient/pattern paint ${value} is not supported.`);
  const erase = paint === "#fff" || paint === "#ffffff" || paint === "white" || paint === "rgb(255,255,255)";
  return { op: erase ? "erase" : "paint", opacity: Math.max(0, Math.min(1, opacity)) };
}

function parseTransform(text) {
  let matrix = IDENTITY;
  const pattern = /(matrix|translate|scale|rotate|skewX|skewY)\s*\(([^)]*)\)/g;
  let match;
  while ((match = pattern.exec(text))) {
    const values = match[2].trim().split(/[\s,]+/).map(Number);
    let next;
    switch (match[1]) {
      case "matrix":
        next = values;
        break;
      case "translate":
        next = [1, 0, 0, 1, values[0], values[1] ?? 0];
        break;
      case "scale":
        next = [values[0], 0, 0, values[1] ?? values[0], 0, 0];
        break;
      case "rotate": {
        const angle = (values[0] * Math.PI) / 180;
        const rotation = [Math.cos(angle), Math.sin(angle), -Math.sin(angle), Math.cos(angle), 0, 0];
        next =
          values.length >= 3
            ? multiply(multiply([1, 0, 0, 1, values[1], values[2]], rotation), [1, 0, 0, 1, -values[1], -values[2]])
            : rotation;
        break;
      }
      case "skewX":
        next = [1, 0, Math.tan((values[0] * Math.PI) / 180), 1, 0, 0];
        break;
      default:
        next = [1, Math.tan((values[0] * Math.PI) / 180), 0, 1, 0, 0];
    }
    matrix = multiply(matrix, next);
  }
  return matrix;
}

function multiply([a1, b1, c1, d1, e1, f1], [a2, b2, c2, d2, e2, f2]) {
  return [
    a1 * a2 + c1 * b2,
    b1 * a2 + d1 * b2,
    a1 * c2 + c1 * d2,
    b1 * c2 + d1 * d2,
    a1 * e2 + c1 * f2 + e1,
    b1 * e2 + d1 * f2 + f1
  ];
}

function apply([a, b, c, d, e, f], [x, y]) {
  return [a * x + c * y + e, b * x + d * y + f];
}

function dedupe(points) {
  const result = [];
  for (const point of points) {
    const last = result.at(-1);
    if (!last || Math.abs(last[0] - point[0]) > 1e-9 || Math.abs(last[1] - point[1]) > 1e-9) result.push(point);
  }
  return result;
}

function geometryOf(node) {
  const a = (key, fallback = 0) => number(node.attrs[key], fallback);
  switch (node.name) {
    case "path":
      return parsePath(node.attrs.d ?? "");
    case "circle":
      return [{ points: ellipsePoints(a("cx"), a("cy"), a("r"), a("r")), closed: true, drawn: true }];
    case "ellipse":
      return [{ points: ellipsePoints(a("cx"), a("cy"), a("rx"), a("ry")), closed: true, drawn: true }];
    case "rect":
      return [{ points: rectPoints(node), closed: true, drawn: true }];
    case "line":
      return [{ points: [[a("x1"), a("y1")], [a("x2"), a("y2")]], closed: false, drawn: true }];
    default: {
      const values = (node.attrs.points ?? "").trim().split(/[\s,]+/).map(Number);
      const points = [];
      for (let index = 0; index + 1 < values.length; index += 2) points.push([values[index], values[index + 1]]);
      return [{ points, closed: node.name === "polygon", drawn: true }];
    }
  }
}

function ellipsePoints(cx, cy, rx, ry) {
  if (!(rx > 0) || !(ry > 0)) return [];
  const count = 160;
  return Array.from({ length: count }, (_, index) => {
    const angle = (index / count) * Math.PI * 2;
    return [cx + rx * Math.cos(angle), cy + ry * Math.sin(angle)];
  });
}

function rectPoints(node) {
  const x = number(node.attrs.x, 0);
  const y = number(node.attrs.y, 0);
  const width = number(node.attrs.width, 0);
  const height = number(node.attrs.height, 0);
  if (!(width > 0) || !(height > 0)) return [];
  let rx = number(node.attrs.rx, Number.NaN);
  let ry = number(node.attrs.ry, Number.NaN);
  if (Number.isNaN(rx)) rx = Number.isNaN(ry) ? 0 : ry;
  if (Number.isNaN(ry)) ry = rx;
  rx = Math.min(Math.max(rx, 0), width / 2);
  ry = Math.min(Math.max(ry, 0), height / 2);
  if (rx === 0 || ry === 0) {
    return [[x, y], [x + width, y], [x + width, y + height], [x, y + height]];
  }
  const corner = (cx, cy, start) =>
    Array.from({ length: 25 }, (_, index) => {
      const angle = start + (index / 24) * (Math.PI / 2);
      return [cx + rx * Math.cos(angle), cy + ry * Math.sin(angle)];
    });
  return [
    ...corner(x + width - rx, y + ry, -Math.PI / 2),
    ...corner(x + width - rx, y + height - ry, 0),
    ...corner(x + rx, y + height - ry, Math.PI / 2),
    ...corner(x + rx, y + ry, Math.PI)
  ];
}

function parsePath(d) {
  const subpaths = [];
  let index = 0;
  const skip = () => {
    while (index < d.length && /[\s,]/.test(d[index])) index += 1;
  };
  const readNumber = () => {
    skip();
    const match = /^[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?/.exec(d.slice(index));
    if (!match) throw new Error(`Bad path data near "${d.slice(index, index + 12)}"`);
    index += match[0].length;
    return Number(match[0]);
  };
  const readFlag = () => {
    skip();
    const flag = d[index];
    if (flag !== "0" && flag !== "1") throw new Error(`Bad arc flag near "${d.slice(index, index + 12)}"`);
    index += 1;
    return flag === "1";
  };
  let current = null;
  let x = 0;
  let y = 0;
  let startX = 0;
  let startY = 0;
  let lastControl = null;
  let lastCommand = "";
  const lineTo = (nx, ny) => {
    current.points.push([nx, ny]);
    current.drawn = true;
    x = nx;
    y = ny;
  };
  const moveTo = (nx, ny) => {
    current = { points: [[nx, ny]], closed: false, drawn: false };
    subpaths.push(current);
    x = startX = nx;
    y = startY = ny;
  };
  const ensure = () => {
    if (!current || current.closed) {
      const reopened = { points: [[x, y]], closed: false, drawn: false };
      subpaths.push(reopened);
      current = reopened;
    }
  };

  while (true) {
    skip();
    if (index >= d.length) break;
    let command = d[index];
    if (/[A-Za-z]/.test(command)) {
      index += 1;
    } else if (lastCommand && lastCommand !== "Z" && lastCommand !== "z") {
      command = lastCommand === "M" ? "L" : lastCommand === "m" ? "l" : lastCommand;
    } else {
      throw new Error(`Unexpected "${command}" in path data; expected a command letter.`);
    }
    const relative = command === command.toLowerCase();
    const upper = command.toUpperCase();
    const ox = relative ? x : 0;
    const oy = relative ? y : 0;
    switch (upper) {
      case "M":
        moveTo(ox + readNumber(), oy + readNumber());
        lastControl = null;
        break;
      case "L":
        ensure();
        lineTo(ox + readNumber(), oy + readNumber());
        lastControl = null;
        break;
      case "H":
        ensure();
        lineTo(ox + readNumber(), y);
        lastControl = null;
        break;
      case "V":
        ensure();
        lineTo(x, oy + readNumber());
        lastControl = null;
        break;
      case "C":
      case "S": {
        ensure();
        let c1;
        if (upper === "C") {
          c1 = [ox + readNumber(), oy + readNumber()];
        } else {
          c1 = lastControl && /[CcSs]/.test(lastCommand) ? [2 * x - lastControl[0], 2 * y - lastControl[1]] : [x, y];
        }
        const c2 = [ox + readNumber(), oy + readNumber()];
        const end = [ox + readNumber(), oy + readNumber()];
        const start = [x, y];
        for (let step = 1; step <= 40; step += 1) {
          const t = step / 40;
          const u = 1 - t;
          lineTo(
            u * u * u * start[0] + 3 * u * u * t * c1[0] + 3 * u * t * t * c2[0] + t * t * t * end[0],
            u * u * u * start[1] + 3 * u * u * t * c1[1] + 3 * u * t * t * c2[1] + t * t * t * end[1]
          );
        }
        lastControl = c2;
        break;
      }
      case "Q":
      case "T": {
        ensure();
        let control;
        if (upper === "Q") {
          control = [ox + readNumber(), oy + readNumber()];
        } else {
          control = lastControl && /[QqTt]/.test(lastCommand) ? [2 * x - lastControl[0], 2 * y - lastControl[1]] : [x, y];
        }
        const end = [ox + readNumber(), oy + readNumber()];
        const start = [x, y];
        for (let step = 1; step <= 32; step += 1) {
          const t = step / 32;
          const u = 1 - t;
          lineTo(
            u * u * start[0] + 2 * u * t * control[0] + t * t * end[0],
            u * u * start[1] + 2 * u * t * control[1] + t * t * end[1]
          );
        }
        lastControl = control;
        break;
      }
      case "A": {
        ensure();
        const rx = readNumber();
        const ry = readNumber();
        const rotation = readNumber();
        const large = readFlag();
        const sweep = readFlag();
        const end = [ox + readNumber(), oy + readNumber()];
        const start = [x, y];
        for (const point of arcPoints(start, rx, ry, rotation, large, sweep, end)) lineTo(point[0], point[1]);
        current.drawn = true;
        lastControl = null;
        break;
      }
      case "Z":
        if (current) {
          current.closed = true;
          current.drawn = true;
        }
        x = startX;
        y = startY;
        lastControl = null;
        break;
      default:
        throw new Error(`Unsupported path command ${command}`);
    }
    // Numbers that follow without a new letter repeat this command (M repeats as L).
    lastCommand = command;
  }
  return subpaths;
}

function arcPoints([x1, y1], rx, ry, rotationDegrees, large, sweep, [x2, y2]) {
  if (x1 === x2 && y1 === y2) return [];
  rx = Math.abs(rx);
  ry = Math.abs(ry);
  if (!rx || !ry) return [[x2, y2]];
  const phi = (rotationDegrees * Math.PI) / 180;
  const cos = Math.cos(phi);
  const sin = Math.sin(phi);
  const dx = (x1 - x2) / 2;
  const dy = (y1 - y2) / 2;
  const x1p = cos * dx + sin * dy;
  const y1p = -sin * dx + cos * dy;
  const lambda = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry);
  if (lambda > 1) {
    rx *= Math.sqrt(lambda);
    ry *= Math.sqrt(lambda);
  }
  const numerator = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p;
  const denominator = rx * rx * y1p * y1p + ry * ry * x1p * x1p;
  let coefficient = Math.sqrt(Math.max(0, numerator / denominator));
  if (large === sweep) coefficient = -coefficient;
  const cxp = (coefficient * rx * y1p) / ry;
  const cyp = (-coefficient * ry * x1p) / rx;
  const cx = cos * cxp - sin * cyp + (x1 + x2) / 2;
  const cy = sin * cxp + cos * cyp + (y1 + y2) / 2;
  const angle = (ux, uy, vx, vy) => Math.atan2(ux * vy - uy * vx, ux * vx + uy * vy);
  const theta = angle(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry);
  let delta = angle((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry);
  if (!sweep && delta > 0) delta -= Math.PI * 2;
  else if (sweep && delta < 0) delta += Math.PI * 2;
  const count = Math.max(6, Math.ceil(Math.abs(delta) / (Math.PI / 120)));
  const points = [];
  for (let step = 1; step <= count; step += 1) {
    const t = theta + (delta * step) / count;
    points.push([
      cx + rx * Math.cos(t) * cos - ry * Math.sin(t) * sin,
      cy + rx * Math.cos(t) * sin + ry * Math.sin(t) * cos
    ]);
  }
  points[points.length - 1] = [x2, y2];
  return points;
}

function boundsOf(shape) {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const subpath of shape.subpaths) {
    for (const [x, y] of subpath.points) {
      minX = Math.min(minX, x);
      minY = Math.min(minY, y);
      maxX = Math.max(maxX, x);
      maxY = Math.max(maxY, y);
    }
  }
  const pad = shape.stroke ? shape.stroke.halfWidth * (shape.stroke.cap === "square" ? Math.SQRT2 : 1) : 0;
  return { minX: minX - pad, minY: minY - pad, maxX: maxX + pad, maxY: maxY + pad };
}

function insideFill(subpaths, rule, px, py) {
  let winding = 0;
  for (const { points } of subpaths) {
    if (points.length < 3) continue;
    for (let index = 0; index < points.length; index += 1) {
      const [x1, y1] = points[index];
      const [x2, y2] = points[(index + 1) % points.length];
      if (y1 <= py) {
        if (y2 > py && (x2 - x1) * (py - y1) - (px - x1) * (y2 - y1) > 0) winding += 1;
      } else if (y2 <= py && (x2 - x1) * (py - y1) - (px - x1) * (y2 - y1) < 0) {
        winding -= 1;
      }
    }
  }
  return rule === "evenodd" ? winding % 2 !== 0 : winding !== 0;
}

function insideStroke(subpaths, halfWidth, cap, px, py) {
  const hw2 = halfWidth * halfWidth;
  for (const { points, closed, drawn } of subpaths) {
    if (!drawn || points.length === 0) continue;
    if (points.length === 1) {
      // Zero-length subpath: round and square caps draw a dot.
      const [x, y] = points[0];
      if (cap === "round" && (px - x) ** 2 + (py - y) ** 2 <= hw2) return true;
      if (cap === "square" && Math.abs(px - x) <= halfWidth && Math.abs(py - y) <= halfWidth) return true;
      continue;
    }
    const segmentCount = closed ? points.length : points.length - 1;
    for (let index = 0; index < segmentCount; index += 1) {
      const [x1, y1] = points[index];
      const [x2, y2] = points[(index + 1) % points.length];
      const dx = x2 - x1;
      const dy = y2 - y1;
      const length = Math.hypot(dx, dy);
      if (length === 0) continue;
      const t = ((px - x1) * dx + (py - y1) * dy) / (length * length);
      let tMin = 0;
      let tMax = 1;
      if (!closed && cap === "square") {
        if (index === 0) tMin = -halfWidth / length;
        if (index === segmentCount - 1) tMax = 1 + halfWidth / length;
      }
      if (t >= tMin && t <= tMax) {
        const perpendicular = Math.abs((px - x1) * dy - (py - y1) * dx) / length;
        if (perpendicular <= halfWidth) return true;
      }
    }
    for (let index = 0; index < points.length; index += 1) {
      const isEnd = !closed && (index === 0 || index === points.length - 1);
      if (isEnd && cap !== "round") continue;
      const [x, y] = points[index];
      if ((px - x) ** 2 + (py - y) ** 2 <= hw2) return true;
    }
  }
  return false;
}

function composite(value, paint, inside) {
  if (!inside) return value;
  return paint.op === "erase" ? value * (1 - paint.opacity) : paint.opacity + value * (1 - paint.opacity);
}

/** Renders to an alpha-only bitmap (Uint8Array, row-major) `pixelWidth` pixels wide. */
export function renderSvg(text, pixelWidth, supersample = 16) {
  const svg = parseSvg(text);
  const { shapes, width, height } = collectShapes(svg, pixelWidth);
  const alpha = new Uint8Array(width * height);
  const samples = supersample * supersample;
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const active = shapes.filter(
        ({ bounds }) => bounds.maxX >= x && bounds.minX <= x + 1 && bounds.maxY >= y && bounds.minY <= y + 1
      );
      if (active.length === 0) continue;
      let total = 0;
      for (let sy = 0; sy < supersample; sy += 1) {
        for (let sx = 0; sx < supersample; sx += 1) {
          const px = x + (sx + 0.5) / supersample;
          const py = y + (sy + 0.5) / supersample;
          let value = 0;
          for (const shape of active) {
            if (shape.fill) value = composite(value, shape.fill, insideFill(shape.subpaths, shape.fill.rule, px, py));
            if (shape.stroke) {
              value = composite(value, shape.stroke, insideStroke(shape.subpaths, shape.stroke.halfWidth, shape.stroke.cap, px, py));
            }
          }
          total += value;
        }
      }
      alpha[y * width + x] = Math.round((total / samples) * 255);
    }
  }
  return { width, height, alpha };
}
