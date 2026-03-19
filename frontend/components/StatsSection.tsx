const STATS = [
    { num: '2,400', sup: '+', label: 'Bất Động Sản Đang Rao', desc: 'cập nhật mỗi ngày' },
    { num: '12,000', sup: '+', label: 'Khách Hàng Hài Lòng', desc: 'trên toàn quốc' },
    { num: '63', sup: '', label: 'Tỉnh Thành Phủ Sóng', desc: 'từ Bắc vào Nam' },
    { num: '98', sup: '%', label: 'Tỷ Lệ Xác Minh', desc: 'pháp lý minh bạch' },
];

export default function StatsSection() {
    return (
        <section className="e-stats e-reveal" style={{ padding: '0', position: 'relative', overflow: 'hidden' }}>

            {/* ══════════════════════════════════════
                ORGANIC CURVE BACKGROUND PATTERNS
            ══════════════════════════════════════ */}

            {/* Layer 1 — Large sweeping gold curves, top-right */}
            <svg
                aria-hidden="true"
                style={{
                    position: 'absolute',
                    top: '-10%', right: '-5%',
                    width: '65%', height: 'auto',
                    opacity: 0.045,
                    pointerEvents: 'none',
                    zIndex: 0,
                }}
                viewBox="0 0 600 500" fill="none" xmlns="http://www.w3.org/2000/svg"
            >
                <path d="M580 20 C480 60, 360 40, 280 120 C200 200, 160 300, 80 360 C20 400, -20 440, -40 500" stroke="#C8A84B" strokeWidth="1" />
                <path d="M600 80 C500 110, 380 90, 300 170 C220 250, 180 350, 100 410 C40 450, 0 490, -20 550" stroke="#C8A84B" strokeWidth="1" />
                <path d="M560 -20 C460 20, 340 0, 260 80 C180 160, 140 260, 60 320 C0 360, -40 400, -60 460" stroke="#C8A84B" strokeWidth="1" />
                <path d="M540 140 C440 160, 320 140, 240 220 C160 300, 120 400, 40 460 C-20 500, -60 530, -80 590" stroke="#C8A84B" strokeWidth="0.7" />
                <path d="M520 200 C420 210, 300 190, 220 270 C140 350, 100 450, 20 510" stroke="#C8A84B" strokeWidth="0.7" />
            </svg>

            {/* Layer 2 — Tighter contour lines, bottom-left */}
            <svg
                aria-hidden="true"
                style={{
                    position: 'absolute',
                    bottom: '-5%', left: '-8%',
                    width: '55%', height: 'auto',
                    opacity: 0.038,
                    pointerEvents: 'none',
                    zIndex: 0,
                }}
                viewBox="0 0 550 420" fill="none" xmlns="http://www.w3.org/2000/svg"
            >
                <path d="M-20 380 C60 320, 140 260, 220 200 C300 140, 380 100, 460 60 C520 30, 560 10, 580 -10" stroke="white" strokeWidth="1" />
                <path d="M-20 340 C60 280, 140 220, 220 160 C300 100, 380 60, 460 20 C520 -10, 560 -30, 580 -50" stroke="white" strokeWidth="1" />
                <path d="M-20 300 C60 240, 140 180, 220 120 C300 60, 380 20, 460 -20" stroke="white" strokeWidth="1" />
                <path d="M-20 420 C80 360, 160 300, 240 240 C320 180, 400 140, 480 100 C540 70, 570 50, 590 30" stroke="white" strokeWidth="0.7" />
                <path d="M-20 260 C60 200, 140 140, 220 80 C300 20, 380 -20, 460 -60" stroke="white" strokeWidth="0.7" />
                <path d="M-20 460 C80 400, 160 340, 240 280 C320 220, 400 180, 480 140" stroke="white" strokeWidth="0.5" />
            </svg>

            {/* Layer 3 — Center subtle blob ellipses */}
            <svg
                aria-hidden="true"
                style={{
                    position: 'absolute',
                    top: '30%', left: '35%',
                    width: '40%', height: 'auto',
                    opacity: 0.025,
                    pointerEvents: 'none',
                    zIndex: 0,
                }}
                viewBox="0 0 400 300" fill="none" xmlns="http://www.w3.org/2000/svg"
            >
                <ellipse cx="200" cy="150" rx="180" ry="90" stroke="white" strokeWidth="1" />
                <ellipse cx="200" cy="150" rx="150" ry="70" stroke="white" strokeWidth="1" />
                <ellipse cx="200" cy="150" rx="120" ry="52" stroke="white" strokeWidth="1" />
                <ellipse cx="200" cy="150" rx="90" ry="36" stroke="white" strokeWidth="0.8" />
                <ellipse cx="200" cy="150" rx="60" ry="22" stroke="white" strokeWidth="0.8" />
                <ellipse cx="200" cy="150" rx="30" ry="10" stroke="white" strokeWidth="0.6" />
            </svg>

            {/* Layer 4 — Vermilion accent arcs, top-left */}
            <svg
                aria-hidden="true"
                style={{
                    position: 'absolute',
                    top: 0, left: 0,
                    width: '30%', height: 'auto',
                    opacity: 0.06,
                    pointerEvents: 'none',
                    zIndex: 0,
                }}
                viewBox="0 0 300 250" fill="none" xmlns="http://www.w3.org/2000/svg"
            >
                <path d="M-30 250 C20 180, 80 120, 150 80 C220 40, 280 20, 330 0" stroke="#C94B2A" strokeWidth="1.5" />
                <path d="M-30 210 C20 140, 80 80, 150 40 C220 0, 280 -20, 330 -40" stroke="#C94B2A" strokeWidth="1.2" />
                <path d="M-30 290 C20 220, 80 160, 150 120 C220 80, 280 60, 330 40" stroke="#C94B2A" strokeWidth="1" />
            </svg>

            {/* ══════════════════════════════════════
                CONTENT
            ══════════════════════════════════════ */}

            {/* Top label bar */}
            <div style={{
                position: 'relative',
                zIndex: 1,
                borderBottom: '1px solid rgba(255,255,255,0.07)',
                padding: '1.4rem 5vw',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
            }}>
                <div className="e-section-label" style={{ marginBottom: 0 }}>
                    Con Số Thực Tế
                </div>
                <span style={{
                    fontFamily: 'var(--e-serif)',
                    fontSize: '0.82rem',
                    fontStyle: 'italic',
                    color: 'rgba(255,255,255,0.20)',
                    fontWeight: 300,
                }}>
                    "Minh bạch — Tin cậy — Bền vững"
                </span>
            </div>

            {/* Stats grid */}
            <div className="e-stats-grid" style={{ marginTop: 0 }}>
                {STATS.map((s, i) => (
                    <div key={s.label} className="e-stat-item" style={{
                        padding: '3rem 2.5rem 3rem',
                        paddingLeft: i === 0 ? '5vw' : undefined,
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        gap: '1rem',
                        position: 'relative',
                    }}>
                        {/* Gold gradient divider line (matching footer style) */}
                        {i < STATS.length - 1 && (
                            <div style={{
                                position: 'absolute',
                                top: 0, right: 0,
                                width: '1px',
                                height: '100%',
                                background: 'linear-gradient(to bottom, transparent 0%, rgba(200,168,75,0.18) 35%, rgba(200,168,75,0.18) 65%, transparent 100%)',
                                pointerEvents: 'none',
                            }} />
                        )}

                        {/* Index number */}
                        <span style={{
                            fontFamily: 'var(--e-sans)',
                            fontSize: '0.58rem',
                            letterSpacing: '0.20em',
                            color: 'var(--e-gold)',
                            fontWeight: 700,
                        }}>
                            0{i + 1}
                        </span>

                        {/* Big number */}
                        <div className="e-stat-num" style={{
                            fontSize: 'clamp(2.6rem, 4.5vw, 4rem)',
                            marginTop: `${i * 0.5}rem`,
                        }}>
                            {s.num}
                            {s.sup && <sup>{s.sup}</sup>}
                        </div>

                        {/* Label + desc */}
                        <div>
                            <div className="e-stat-label">{s.label}</div>
                            <div style={{
                                fontFamily: 'var(--e-sans)',
                                fontSize: '0.70rem',
                                color: 'rgba(255,255,255,0.18)',
                                marginTop: '4px',
                                fontWeight: 400,
                                fontStyle: 'italic',
                            }}>
                                {s.desc}
                            </div>
                        </div>
                    </div>
                ))}
            </div>

            {/* Bottom gold accent line */}
            <div style={{
                position: 'relative',
                zIndex: 1,
                height: '3px',
                background: 'linear-gradient(to right, var(--e-gold) 0%, transparent 60%)',
            }} />
        </section>
    );
}