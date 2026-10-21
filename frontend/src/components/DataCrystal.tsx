import { useEffect, useRef, useState } from "react";

interface Point3D {
  x: number;
  y: number;
  z: number;
}

interface Face {
  indices: [number, number, number];
  baseColor: string;
  wireColor: string;
}

export default function DataCrystal() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [isReducedMotion, setIsReducedMotion] = useState(false);
  const mouseRef = useRef({ x: 0, y: 0, targetX: 0, targetY: 0 });

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setIsReducedMotion(mq.matches);
    const handler = (e: MediaQueryListEvent) => setIsReducedMotion(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let angleX = 0.4;
    let angleY = 0.6;
    let angleZ = 0.1;

    // Define vertices of an octagonal bipyramidal cryptographic crystal
    const rawVertices: Point3D[] = [
      { x: 0, y: -160, z: 0 }, // Top apex
      { x: 0, y: 160, z: 0 },  // Bottom apex
      // Equatorial ring
      { x: 90, y: -20, z: 0 },
      { x: 64, y: 10, z: 64 },
      { x: 0, y: -20, z: 90 },
      { x: -64, y: 10, z: 64 },
      { x: -90, y: -20, z: 0 },
      { x: -64, y: 10, z: -64 },
      { x: 0, y: -20, z: -90 },
      { x: 64, y: 10, z: -64 },
      // Inner core octahedron vertices
      { x: 0, y: -50, z: 0 },
      { x: 0, y: 50, z: 0 },
      { x: 35, y: 0, z: 0 },
      { x: 0, y: 0, z: 35 },
      { x: -35, y: 0, z: 0 },
      { x: 0, y: 0, z: -35 },
    ];

    // Faces connecting apex to equator
    const faces: Face[] = [
      // Upper pyramid
      { indices: [0, 2, 3], baseColor: "rgba(183, 243, 107, 0.22)", wireColor: "#B7F36B" },
      { indices: [0, 3, 4], baseColor: "rgba(183, 243, 107, 0.14)", wireColor: "#9ee64e" },
      { indices: [0, 4, 5], baseColor: "rgba(183, 243, 107, 0.28)", wireColor: "#B7F36B" },
      { indices: [0, 5, 6], baseColor: "rgba(41, 33, 60, 0.55)", wireColor: "#B7F36B" },
      { indices: [0, 6, 7], baseColor: "rgba(24, 45, 50, 0.45)", wireColor: "#6ee7b7" },
      { indices: [0, 7, 8], baseColor: "rgba(41, 33, 60, 0.65)", wireColor: "#B7F36B" },
      { indices: [0, 8, 9], baseColor: "rgba(183, 243, 107, 0.18)", wireColor: "#B7F36B" },
      { indices: [0, 9, 2], baseColor: "rgba(183, 243, 107, 0.26)", wireColor: "#B7F36B" },
      // Lower pyramid
      { indices: [1, 3, 2], baseColor: "rgba(183, 243, 107, 0.16)", wireColor: "#B7F36B" },
      { indices: [1, 4, 3], baseColor: "rgba(24, 45, 50, 0.5)", wireColor: "#B7F36B" },
      { indices: [1, 5, 4], baseColor: "rgba(183, 243, 107, 0.24)", wireColor: "#B7F36B" },
      { indices: [1, 6, 5], baseColor: "rgba(41, 33, 60, 0.7)", wireColor: "#B7F36B" },
      { indices: [1, 7, 6], baseColor: "rgba(183, 243, 107, 0.12)", wireColor: "#B7F36B" },
      { indices: [1, 8, 7], baseColor: "rgba(24, 45, 50, 0.6)", wireColor: "#6ee7b7" },
      { indices: [1, 9, 8], baseColor: "rgba(41, 33, 60, 0.5)", wireColor: "#B7F36B" },
      { indices: [1, 2, 9], baseColor: "rgba(183, 243, 107, 0.3)", wireColor: "#B7F36B" },
    ];

    // Background floating orbital particles
    const particles = Array.from({ length: 42 }, () => ({
      x: (Math.random() - 0.5) * 520,
      y: (Math.random() - 0.5) * 440,
      z: (Math.random() - 0.5) * 300,
      size: Math.random() * 2 + 1,
      speed: (Math.random() * 0.3 + 0.1) * (Math.random() > 0.5 ? 1 : -1),
      alpha: Math.random() * 0.6 + 0.2,
    }));

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const nx = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
      const ny = ((e.clientY - rect.top) / rect.height - 0.5) * 2;
      mouseRef.current.targetX = nx * 0.45;
      mouseRef.current.targetY = ny * 0.45;
    };

    window.addEventListener("mousemove", handleMouseMove);

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
        canvas.width = width * dpr;
        canvas.height = height * dpr;
      }
    };
    resize();
    window.addEventListener("resize", resize);

    let lastTime = performance.now();

    const render = (now: number) => {
      const dt = (now - lastTime) / 1000;
      lastTime = now;

      // Smooth mouse lerp
      mouseRef.current.x += (mouseRef.current.targetX - mouseRef.current.x) * 0.05;
      mouseRef.current.y += (mouseRef.current.targetY - mouseRef.current.y) * 0.05;

      if (!isReducedMotion) {
        angleY += 0.45 * dt;
        angleX = Math.sin(now * 0.0006) * 0.25 + mouseRef.current.y;
        angleZ = Math.cos(now * 0.0008) * 0.15;
      }

      const dpr = window.devicePixelRatio || 1;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.save();
      ctx.scale(dpr, dpr);

      const cx = canvas.clientWidth / 2;
      const cy = canvas.clientHeight / 2 + Math.sin(now * 0.0018) * 12;

      // 3D rotation matrix calculations
      const cosY = Math.cos(angleY + mouseRef.current.x);
      const sinY = Math.sin(angleY + mouseRef.current.x);
      const cosX = Math.cos(angleX);
      const sinX = Math.sin(angleX);
      const cosZ = Math.cos(angleZ);
      const sinZ = Math.sin(angleZ);

      const project = (p: Point3D): { x: number; y: number; z: number } => {
        // Rotate Y
        let x1 = p.x * cosY + p.z * sinY;
        let y1 = p.y;
        let z1 = -p.x * sinY + p.z * cosY;

        // Rotate X
        let x2 = x1;
        let y2 = y1 * cosX - z1 * sinX;
        let z2 = y1 * sinX + z1 * cosX;

        // Rotate Z
        let x3 = x2 * cosZ - y2 * sinZ;
        let y3 = x2 * sinZ + y2 * cosZ;
        let z3 = z2;

        const fov = 480;
        const scale = fov / (fov + z3);
        return {
          x: cx + x3 * scale,
          y: cy + y3 * scale,
          z: z3,
        };
      };

      // Draw subtle orbital rings
      ctx.save();
      ctx.beginPath();
      ctx.ellipse(cx, cy, 180, 52, angleZ + mouseRef.current.x * 0.2, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(183, 243, 107, 0.18)";
      ctx.lineWidth = 1.2;
      ctx.setLineDash([4, 8]);
      ctx.stroke();

      ctx.beginPath();
      ctx.ellipse(cx, cy, 210, 68, -angleZ - 0.2, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(24, 45, 50, 0.45)";
      ctx.lineWidth = 1;
      ctx.setLineDash([2, 10]);
      ctx.stroke();
      ctx.restore();

      // Render floating particles
      particles.forEach(p => {
        if (!isReducedMotion) {
          p.y += p.speed;
          if (p.y > 220) p.y = -220;
          if (p.y < -220) p.y = 220;
        }
        const proj = project(p);
        ctx.beginPath();
        ctx.arc(proj.x, proj.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(183, 243, 107, ${p.alpha * 0.7})`;
        ctx.fill();
      });

      // Project vertices
      const projected = rawVertices.map(project);

      // Sort faces by average depth for painter's algorithm
      const sortedFaces = faces
        .map(face => {
          const zAvg =
            (projected[face.indices[0]].z +
              projected[face.indices[1]].z +
              projected[face.indices[2]].z) /
            3;
          return { ...face, zAvg };
        })
        .sort((a, b) => b.zAvg - a.zAvg);

      // Render faces
      sortedFaces.forEach(face => {
        const p0 = projected[face.indices[0]];
        const p1 = projected[face.indices[1]];
        const p2 = projected[face.indices[2]];

        ctx.beginPath();
        ctx.moveTo(p0.x, p0.y);
        ctx.lineTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.closePath();

        // Facet fill
        ctx.fillStyle = face.baseColor;
        ctx.fill();

        // Edge stroke
        ctx.strokeStyle = face.wireColor;
        ctx.lineWidth = 1.4;
        ctx.stroke();
      });

      // Render glowing vertices
      projected.slice(0, 10).forEach(p => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
        ctx.fillStyle = "#B7F36B";
        ctx.shadowColor = "#B7F36B";
        ctx.shadowBlur = 10;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      ctx.restore();

      animId = requestAnimationFrame(render);
    };

    animId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("resize", resize);
    };
  }, [isReducedMotion]);

  return (
    <div ref={containerRef} className="data-crystal-container" aria-hidden="true">
      <div className="crystal-ambient-glow" />
      <canvas ref={canvasRef} className="data-crystal-canvas" />
      <div className="crystal-telemetry-badge">
        <span className="crystal-badge-ring" />
        <span className="mono">SHA256 // CRYPTOGRAPHIC CORE ACTIVE</span>
      </div>
    </div>
  );
}
