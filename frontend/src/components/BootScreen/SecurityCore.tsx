import React from "react";
import styles from "./BootScreen.module.css";

export const SecurityCore: React.FC = () => {
  return (
    <div className={styles.coreWrapper} aria-label="KAVACH-X Security Core Animation">
      {/* Background Orbital Arc */}
      <svg className={styles.orbitalSvg} viewBox="0 0 640 320" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path
          d="M 40 280 A 280 200 0 0 1 600 280"
          stroke="rgba(185, 167, 232, 0.22)"
          strokeWidth="1.2"
          strokeDasharray="4 4"
        />
        <path
          d="M 90 280 A 230 160 0 0 1 550 280"
          stroke="rgba(183, 243, 107, 0.25)"
          strokeWidth="1"
        />
        {/* Orbital nodes */}
        <circle cx="160" cy="165" r="3" fill="#B7F36B" className={styles.nodeGlow} />
        <circle cx="320" cy="120" r="4" fill="#B7F36B" className={styles.nodeGlowPulse} />
        <circle cx="480" cy="165" r="3" fill="#B9A7E8" className={styles.nodeGlow} />
      </svg>

      {/* Floating 3-Layer Glass Structure */}
      <div className={styles.isometricStage}>
        {/* Top Glass Layer */}
        <div className={`${styles.glassLayer} ${styles.topLayer}`}>
          <div className={styles.glassReflection} />
          <div className={styles.layerGlowRim} />
        </div>

        {/* Central Glowing Lime Shield */}
        <div className={styles.centralShieldContainer}>
          <div className={styles.shieldAura} />
          <svg
            className={styles.shieldSvg}
            viewBox="0 0 64 74"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <defs>
              <linearGradient id="shieldGrad" x1="32" y1="0" x2="32" y2="74" gradientUnits="userSpaceOnUse">
                <stop stopColor="#B7F36B" />
                <stop offset="0.6" stopColor="#84CC16" />
                <stop offset="1" stopColor="#4D7C0F" />
              </linearGradient>
              <filter id="shieldGlowFilter" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="5" result="glow" />
                <feComposite in="SourceGraphic" in2="glow" operator="over" />
              </filter>
            </defs>

            {/* Outer Shield Boundary */}
            <path
              d="M32 3L60 15V36C60 55 48 68 32 72C16 68 4 55 4 36V15L32 3Z"
              fill="rgba(183, 243, 107, 0.12)"
              stroke="url(#shieldGrad)"
              strokeWidth="2.5"
              strokeLinejoin="round"
              filter="url(#shieldGlowFilter)"
            />

            {/* Inner Shield Facet */}
            <path
              d="M32 9L54 19V36C54 51 44 62 32 66C20 62 10 51 10 36V19L32 9Z"
              fill="rgba(23, 16, 37, 0.65)"
              stroke="rgba(183, 243, 107, 0.45)"
              strokeWidth="1"
            />

            {/* Verified Security Checkmark */}
            <path
              d="M22 36L29 43L43 27"
              stroke="#B7F36B"
              strokeWidth="3.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>

        {/* Middle Glass Layer with Circuit Matrix */}
        <div className={`${styles.glassLayer} ${styles.midLayer}`}>
          <div className={styles.circuitMatrix} />
          <div className={styles.scanBeam} />
        </div>

        {/* Bottom Glass Layer / Foundation Pedestal */}
        <div className={`${styles.glassLayer} ${styles.botLayer}`}>
          <div className={styles.pedestalEdge} />
        </div>
      </div>
    </div>
  );
};

export default SecurityCore;
