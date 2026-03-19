import { useState, useRef, useEffect, useCallback } from 'react';
import {
    Search, MapPin, SlidersHorizontal, X,
    Bed, Bath, LayoutGrid, Check, ChevronDown,
    Sparkles,
} from 'lucide-react';

/* ══════════════════════════════════════════
   TYPES
══════════════════════════════════════════ */
const TABS = ['Cho Thuê', 'Mua Bán', 'Dự Án Mới', 'Thương Mại'] as const;
type Tab = (typeof TABS)[number];

export interface SearchParams {
    tab: Tab;
    location: string;
    types: string[];
    priceMin: number;
    priceMax: number;
    areaMin: number;
    areaMax: number;
    bedrooms: string[];
    bathrooms: string[];
}

interface SearchSectionProps {
    onSearch?: (params: SearchParams) => void;
    loading?: boolean;
}

/* ══════════════════════════════════════════
   CONSTANTS
══════════════════════════════════════════ */
const PROPERTY_TYPES = [
    { label: 'Căn Hộ', value: 'apartment' },
    { label: 'Biệt Thự', value: 'villa' },
    { label: 'Nhà Phố', value: 'house' },
    { label: 'Studio', value: 'studio' },
    { label: 'Văn Phòng', value: 'office' },
    { label: 'Đất Nền', value: 'land' },
    { label: 'Shophouse', value: 'shophouse' },
    { label: 'Penthouse', value: 'penthouse' },
];

const BEDROOM_OPTS = ['1', '2', '3', '4', '5+'];
const BATHROOM_OPTS = ['1', '2', '3', '4+'];
const QUICK_TAGS = ['Penthouse Quận 1', 'Biệt thự Riviera', 'Căn hộ view sông', 'Shophouse mặt tiền'];

const PRICE_BUY_MARKS = [0, 2, 5, 10, 20, 50];   // tỷ
const PRICE_RENT_MARKS = [0, 5, 15, 30, 60, 100]; // triệu
const AREA_MARKS = [0, 30, 60, 100, 200, 500]; // m²

/* ══════════════════════════════════════════
   DUAL RANGE SLIDER
══════════════════════════════════════════ */
function DualRange({
    marks, valueMin, valueMax, formatTick, onChange,
}: {
    marks: number[];
    valueMin: number;
    valueMax: number;
    formatTick: (v: number) => string;
    onChange: (min: number, max: number) => void;
}) {
    const trackRef = useRef<HTMLDivElement>(null);
    const dragging = useRef<'min' | 'max' | null>(null);
    const min = marks[0], max = marks[marks.length - 1];
    const pct = (v: number) => ((v - min) / (max - min)) * 100;

    const snap = useCallback((raw: number) => {
        let closest = marks[0];
        marks.forEach(m => { if (Math.abs(m - raw) < Math.abs(closest - raw)) closest = m; });
        return closest;
    }, [marks]);

    const getVal = useCallback((clientX: number) => {
        const rect = trackRef.current?.getBoundingClientRect();
        if (!rect) return min;
        const ratio = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
        return snap(min + ratio * (max - min));
    }, [min, max, snap]);

    useEffect(() => {
        const mv = (e: MouseEvent | TouchEvent) => {
            if (!dragging.current) return;
            const x = 'touches' in e ? e.touches[0].clientX : e.clientX;
            const v = getVal(x);
            if (dragging.current === 'min') onChange(Math.min(v, valueMax), valueMax);
            else onChange(valueMin, Math.max(v, valueMin));
        };
        const up = () => { dragging.current = null; };
        window.addEventListener('mousemove', mv);
        window.addEventListener('mouseup', up);
        window.addEventListener('touchmove', mv, { passive: true });
        window.addEventListener('touchend', up);
        return () => {
            window.removeEventListener('mousemove', mv);
            window.removeEventListener('mouseup', up);
            window.removeEventListener('touchmove', mv);
            window.removeEventListener('touchend', up);
        };
    }, [getVal, onChange, valueMin, valueMax]);

    return (
        <div>
            {/* Value display */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 20 }}>
                <div>
                    <div style={{ fontSize: '0.58rem', textTransform: 'uppercase', letterSpacing: '.14em', color: 'var(--e-light-muted)', fontWeight: 600, marginBottom: 3, fontFamily: 'var(--e-sans)' }}>Từ</div>
                    <div style={{ fontFamily: 'var(--e-serif)', fontSize: '1.3rem', fontWeight: 500, color: 'var(--e-charcoal)' }}>{formatTick(valueMin)}</div>
                </div>
                <div style={{ width: 24, height: 1, background: 'var(--e-beige)', margin: '0 8px', alignSelf: 'center' }} />
                <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '0.58rem', textTransform: 'uppercase', letterSpacing: '.14em', color: 'var(--e-light-muted)', fontWeight: 600, marginBottom: 3, fontFamily: 'var(--e-sans)' }}>Đến</div>
                    <div style={{ fontFamily: 'var(--e-serif)', fontSize: '1.3rem', fontWeight: 500, color: 'var(--e-charcoal)' }}>
                        {valueMax >= max ? `${formatTick(max)}+` : formatTick(valueMax)}
                    </div>
                </div>
            </div>

            {/* Track */}
            <div ref={trackRef} style={{ position: 'relative', height: 3, background: 'var(--e-beige)', borderRadius: 2, margin: '0 9px 14px', cursor: 'pointer' }}>
                <div style={{
                    position: 'absolute', height: '100%', background: 'var(--e-gold)', borderRadius: 2,
                    left: `${pct(valueMin)}%`, width: `${pct(valueMax) - pct(valueMin)}%`,
                }} />
                {(['min', 'max'] as const).map(side => (
                    <div key={side}
                        onMouseDown={e => { e.preventDefault(); dragging.current = side; }}
                        onTouchStart={() => { dragging.current = side; }}
                        style={{
                            position: 'absolute', top: '50%',
                            left: `${pct(side === 'min' ? valueMin : valueMax)}%`,
                            transform: 'translate(-50%,-50%)',
                            width: 18, height: 18, borderRadius: '50%',
                            background: '#fff', border: '2px solid var(--e-gold)',
                            cursor: 'grab', touchAction: 'none',
                            boxShadow: '0 1px 8px rgba(140,110,63,.3)', zIndex: 2,
                            transition: 'transform .1s',
                        }}
                        onMouseEnter={e => e.currentTarget.style.transform = 'translate(-50%,-50%) scale(1.2)'}
                        onMouseLeave={e => e.currentTarget.style.transform = 'translate(-50%,-50%) scale(1)'}
                    />
                ))}
            </div>

            {/* Tick marks */}
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0 4px' }}>
                {marks.map(m => (
                    <button key={m} onClick={() => {
                        const dMin = Math.abs(m - valueMin), dMax = Math.abs(m - valueMax);
                        if (dMin <= dMax) onChange(Math.min(m, valueMax), valueMax);
                        else onChange(valueMin, Math.max(m, valueMin));
                    }} style={{
                        background: 'none', border: 'none', cursor: 'pointer',
                        fontSize: '0.62rem', color: (m >= valueMin && m <= valueMax) ? 'var(--e-gold)' : 'var(--e-light-muted)',
                        fontWeight: (m >= valueMin && m <= valueMax) ? 600 : 400,
                        fontFamily: 'var(--e-sans)', padding: '4px 0', transition: 'color .2s',
                    }}>
                        {formatTick(m)}
                    </button>
                ))}
            </div>
        </div>
    );
}

/* ══════════════════════════════════════════
   CHIP
══════════════════════════════════════════ */
function Chip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
    return (
        <button onClick={onClick} style={{
            padding: '7px 15px',
            borderRadius: 2,
            border: `1px solid ${active ? 'var(--e-charcoal)' : 'var(--e-beige)'}`,
            background: active ? 'var(--e-charcoal)' : 'transparent',
            color: active ? 'var(--e-white)' : 'var(--e-muted)',
            fontSize: '0.72rem', fontWeight: active ? 600 : 400,
            cursor: 'pointer', fontFamily: 'var(--e-sans)',
            transition: 'all .18s',
            display: 'inline-flex', alignItems: 'center', gap: 6,
            letterSpacing: '.03em',
        }}
            onMouseEnter={e => { if (!active) { e.currentTarget.style.borderColor = 'var(--e-charcoal)'; e.currentTarget.style.color = 'var(--e-charcoal)'; } }}
            onMouseLeave={e => { if (!active) { e.currentTarget.style.borderColor = 'var(--e-beige)'; e.currentTarget.style.color = 'var(--e-muted)'; } }}
        >
            {active && <Check size={11} strokeWidth={3} />}
            {label}
        </button>
    );
}

/* ══════════════════════════════════════════
   SECTION TITLE inside drawer
══════════════════════════════════════════ */
function DrawerSection({ title, children }: { title: string; children: React.ReactNode }) {
    return (
        <div style={{ marginBottom: '2rem' }}>
            <div style={{
                fontSize: '0.6rem', textTransform: 'uppercase', letterSpacing: '.2em',
                color: 'var(--e-gold)', fontWeight: 700, fontFamily: 'var(--e-sans)',
                marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: 10,
            }}>
                <span style={{ display: 'block', width: 20, height: 1, background: 'var(--e-gold)' }} />
                {title}
            </div>
            {children}
        </div>
    );
}

/* ══════════════════════════════════════════
   MAIN COMPONENT
══════════════════════════════════════════ */
export default function SearchSection({ onSearch, loading }: SearchSectionProps) {
    const [tab, setTab] = useState<Tab>('Mua Bán');
    const [location, setLocation] = useState('');
    const [types, setTypes] = useState<string[]>([]);
    const [bedrooms, setBedrooms] = useState<string[]>([]);
    const [bathrooms, setBathrooms] = useState<string[]>([]);
    const [drawerOpen, setDrawerOpen] = useState(false);

    const isRent = tab === 'Cho Thuê';
    const priceMarks = isRent ? PRICE_RENT_MARKS : PRICE_BUY_MARKS;
    const [priceMin, setPriceMin] = useState(priceMarks[0]);
    const [priceMax, setPriceMax] = useState(priceMarks[priceMarks.length - 1]);
    const [areaMin, setAreaMin] = useState(AREA_MARKS[0]);
    const [areaMax, setAreaMax] = useState(AREA_MARKS[AREA_MARKS.length - 1]);

    const drawerRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        setPriceMin(priceMarks[0]);
        setPriceMax(priceMarks[priceMarks.length - 1]);
    }, [tab]);

    // Close drawer on outside click
    useEffect(() => {
        if (!drawerOpen) return;
        const fn = (e: MouseEvent) => {
            if (drawerRef.current && !drawerRef.current.contains(e.target as Node)) setDrawerOpen(false);
        };
        const t = setTimeout(() => document.addEventListener('mousedown', fn), 0);
        return () => { clearTimeout(t); document.removeEventListener('mousedown', fn); };
    }, [drawerOpen]);

    // Close on Escape
    useEffect(() => {
        const fn = (e: KeyboardEvent) => { if (e.key === 'Escape') setDrawerOpen(false); };
        document.addEventListener('keydown', fn);
        return () => document.removeEventListener('keydown', fn);
    }, []);

    const toggleArr = (arr: string[], val: string, set: (v: string[]) => void) =>
        set(arr.includes(val) ? arr.filter(x => x !== val) : [...arr, val]);

    const reset = () => {
        setTypes([]); setBedrooms([]); setBathrooms([]);
        setPriceMin(priceMarks[0]); setPriceMax(priceMarks[priceMarks.length - 1]);
        setAreaMin(AREA_MARKS[0]); setAreaMax(AREA_MARKS[AREA_MARKS.length - 1]);
    };

    const activeCount =
        types.length + bedrooms.length + bathrooms.length +
        (priceMin > priceMarks[0] || priceMax < priceMarks[priceMarks.length - 1] ? 1 : 0) +
        (areaMin > AREA_MARKS[0] || areaMax < AREA_MARKS[AREA_MARKS.length - 1] ? 1 : 0);

    const handleSearch = () => {
        setDrawerOpen(false);
        onSearch?.({ tab, location, types, priceMin, priceMax, areaMin, areaMax, bedrooms, bathrooms });
    };

    const fmtPrice = (v: number) => isRent ? `${v} tr` : `${v} tỷ`;
    const fmtArea = (v: number) => `${v} m²`;

    /* Active filter summary tags for bar */
    const summaryTags: string[] = [
        ...types.map(t => PROPERTY_TYPES.find(p => p.value === t)?.label ?? t),
        ...(bedrooms.length > 0 ? [`${bedrooms.join('/')} PN`] : []),
        ...(priceMin > priceMarks[0] || priceMax < priceMarks[priceMarks.length - 1]
            ? [`${fmtPrice(priceMin)}–${priceMax >= priceMarks[priceMarks.length - 1] ? fmtPrice(priceMax) + '+' : fmtPrice(priceMax)}`] : []),
        ...(areaMin > AREA_MARKS[0] || areaMax < AREA_MARKS[AREA_MARKS.length - 1]
            ? [`${fmtArea(areaMin)}–${areaMax >= AREA_MARKS[AREA_MARKS.length - 1] ? fmtArea(areaMax) + '+' : fmtArea(areaMax)}`] : []),
    ];

    return (
        <>
            <section id="search" style={{
                background: '#fff',
                borderTop: '1px solid var(--e-beige)',
                borderBottom: '1px solid var(--e-beige)',
                padding: '3.5rem 5vw 4rem',
            }}>
                {/* Heading */}
                <div className="e-reveal" style={{ marginBottom: '2rem' }}>
                    <div style={{
                        fontSize: '0.58rem', fontWeight: 600, letterSpacing: '.22em',
                        textTransform: 'uppercase', color: 'var(--e-gold)',
                        fontFamily: 'var(--e-sans)', marginBottom: '0.5rem',
                        display: 'flex', alignItems: 'center', gap: '0.8rem',
                    }}>
                        <span style={{ display: 'block', width: '1.5rem', height: '1.5px', background: 'var(--e-gold)' }} />
                        Tìm Kiếm
                    </div>
                    <h2 style={{
                        fontFamily: 'var(--e-serif)', fontSize: 'clamp(1.5rem,2.5vw,2rem)',
                        fontWeight: 700, color: 'var(--e-charcoal)', lineHeight: 1.1, margin: 0,
                    }}>
                        Tìm Bất Động Sản{' '}
                        <em style={{ fontStyle: 'italic', fontWeight: 400, opacity: .55 }}>Phù Hợp</em>
                    </h2>
                </div>

                <div className="e-reveal">
                    {/* Tabs */}
                    <div style={{ display: 'flex', gap: 0, marginBottom: '1.5rem', width: 'fit-content', border: '1px solid rgba(140,110,63,.35)' }}>
                        {TABS.map(t => (
                            <button key={t} onClick={() => setTab(t)} style={{
                                padding: '9px 22px',
                                background: tab === t ? 'var(--e-charcoal)' : 'transparent',
                                color: tab === t ? 'var(--e-white)' : 'var(--e-muted)',
                                border: 'none',
                                borderRight: t !== 'Thương Mại' ? '1px solid rgba(140,110,63,.25)' : 'none',
                                cursor: 'pointer', fontSize: '0.72rem', fontWeight: 600,
                                letterSpacing: '.1em', textTransform: 'uppercase',
                                fontFamily: 'var(--e-sans)', transition: 'all .2s',
                            }}>
                                {t}
                            </button>
                        ))}
                    </div>

                    {/* Search bar */}
                    <div style={{ display: 'flex', border: '1px solid var(--e-beige)' }}>
                        {/* Location */}
                        <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0 1.25rem', borderRight: '1px solid var(--e-beige)', minWidth: 0 }}>
                            <MapPin size={16} style={{ flexShrink: 0, color: 'var(--e-gold)' }} />
                            <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ fontSize: '0.56rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.14em', color: 'var(--e-light-muted)', marginBottom: 3, fontFamily: 'var(--e-sans)' }}>Địa Điểm</div>
                                <input
                                    ref={inputRef}
                                    type="text"
                                    placeholder="Khu vực, dự án, từ khoá..."
                                    value={location}
                                    onChange={e => setLocation(e.target.value)}
                                    onKeyDown={e => e.key === 'Enter' && handleSearch()}
                                    style={{
                                        width: '100%', border: 'none', background: 'transparent',
                                        outline: 'none', fontSize: '0.88rem', fontWeight: 500,
                                        color: 'var(--e-charcoal)', fontFamily: 'var(--e-sans)',
                                        padding: '12px 0',
                                    }}
                                />
                            </div>
                            {location && (
                                <button onClick={() => setLocation('')} style={{ background: 'var(--e-cream)', border: 'none', borderRadius: '50%', width: 22, height: 22, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: 'var(--e-muted)', fontSize: '0.7rem', flexShrink: 0 }}>
                                    ✕
                                </button>
                            )}
                        </div>

                        {/* Active summary chips */}
                        {summaryTags.length > 0 && (
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0 14px', borderRight: '1px solid var(--e-beige)', overflow: 'hidden', maxWidth: 280 }}>
                                {summaryTags.slice(0, 3).map((tag, i) => (
                                    <span key={i} style={{ padding: '4px 10px', background: 'var(--e-cream)', border: '1px solid var(--e-beige)', fontSize: '0.68rem', color: 'var(--e-charcoal)', fontWeight: 500, whiteSpace: 'nowrap', fontFamily: 'var(--e-sans)' }}>
                                        {tag}
                                    </span>
                                ))}
                                {summaryTags.length > 3 && (
                                    <span style={{ fontSize: '0.68rem', color: 'var(--e-muted)', whiteSpace: 'nowrap', fontFamily: 'var(--e-sans)' }}>+{summaryTags.length - 3}</span>
                                )}
                            </div>
                        )}

                        {/* Filter button */}
                        <button
                            onClick={() => setDrawerOpen(true)}
                            style={{
                                display: 'flex', alignItems: 'center', gap: 8,
                                padding: '0 22px', background: 'transparent',
                                border: 'none', borderRight: '1px solid var(--e-beige)',
                                cursor: 'pointer', color: 'var(--e-charcoal)',
                                fontFamily: 'var(--e-sans)', fontSize: '0.72rem', fontWeight: 600,
                                letterSpacing: '.1em', textTransform: 'uppercase',
                                transition: 'background .15s', position: 'relative', whiteSpace: 'nowrap',
                            }}
                            onMouseEnter={e => e.currentTarget.style.background = 'var(--e-cream)'}
                            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                        >
                            <SlidersHorizontal size={14} />
                            Bộ Lọc
                            {activeCount > 0 && (
                                <span style={{
                                    position: 'absolute', top: 10, right: 8,
                                    width: 16, height: 16, borderRadius: '50%',
                                    background: 'var(--e-gold)', color: '#fff',
                                    fontSize: '0.55rem', fontWeight: 700,
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    fontFamily: 'var(--e-sans)',
                                }}>{activeCount}</span>
                            )}
                        </button>

                        {/* Search btn */}
                        <button
                            onClick={handleSearch}
                            disabled={loading}
                            style={{
                                display: 'flex', alignItems: 'center', gap: 8,
                                padding: '0 32px', background: 'var(--e-charcoal)',
                                color: 'var(--e-white)', border: 'none', cursor: loading ? 'not-allowed' : 'pointer',
                                fontFamily: 'var(--e-sans)', fontSize: '0.72rem', fontWeight: 700,
                                letterSpacing: '.14em', textTransform: 'uppercase',
                                transition: 'background .2s', opacity: loading ? .7 : 1,
                            }}
                            onMouseEnter={e => { if (!loading) e.currentTarget.style.background = 'var(--e-gold)'; }}
                            onMouseLeave={e => e.currentTarget.style.background = 'var(--e-charcoal)'}
                        >
                            {loading
                                ? <div style={{ width: 14, height: 14, border: '2px solid rgba(255,255,255,.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'ss-spin .8s linear infinite' }} />
                                : <Search size={14} />
                            }
                            Tìm
                        </button>
                    </div>

                    {/* Bottom quick tags */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '1rem', flexWrap: 'wrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, opacity: .6 }}>
                            <Sparkles size={11} style={{ color: 'var(--e-gold)' }} />
                            <span style={{ fontSize: '0.6rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.16em', color: 'var(--e-muted)', fontFamily: 'var(--e-sans)' }}>Đề xuất</span>
                        </div>
                        {QUICK_TAGS.map(tag => (
                            <button key={tag} onClick={() => { setLocation(tag); handleSearch(); }} style={{
                                background: 'none', border: 'none', padding: 0,
                                fontSize: '0.74rem', color: 'var(--e-muted)',
                                textDecoration: 'underline', textUnderlineOffset: 3,
                                cursor: 'pointer', fontFamily: 'var(--e-sans)',
                                transition: 'color .2s',
                            }}
                                onMouseEnter={e => e.currentTarget.style.color = 'var(--e-gold)'}
                                onMouseLeave={e => e.currentTarget.style.color = 'var(--e-muted)'}
                            >{tag}</button>
                        ))}
                    </div>
                </div>
            </section>

            {/* ══════════════════════════════════════════
                FILTER DRAWER (bottom sheet)
            ══════════════════════════════════════════ */}

            {/* Backdrop */}
            <div style={{
                position: 'fixed', inset: 0, zIndex: 200,
                background: 'rgba(26,23,20,.45)',
                opacity: drawerOpen ? 1 : 0,
                pointerEvents: drawerOpen ? 'auto' : 'none',
                transition: 'opacity .3s',
                backdropFilter: drawerOpen ? 'blur(3px)' : 'none',
            }} />

            {/* Drawer panel */}
            <div ref={drawerRef} style={{
                position: 'fixed', bottom: 0, left: 0, right: 0,
                zIndex: 201,
                background: 'var(--e-white)',
                borderTop: '1px solid var(--e-beige)',
                boxShadow: '0 -24px 80px rgba(26,23,20,.18)',
                transform: drawerOpen ? 'translateY(0)' : 'translateY(100%)',
                transition: 'transform .38s cubic-bezier(0.22,1,0.36,1)',
                maxHeight: '88vh',
                display: 'flex', flexDirection: 'column',
                borderRadius: '16px 16px 0 0',
            }}>
                {/* Drag handle */}
                <div style={{ display: 'flex', justifyContent: 'center', padding: '14px 0 0' }}>
                    <div style={{ width: 36, height: 4, borderRadius: 2, background: 'var(--e-beige)' }} />
                </div>

                {/* Drawer header */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 2rem 16px', borderBottom: '1px solid var(--e-beige)', flexShrink: 0 }}>
                    <div>
                        <div style={{ fontSize: '0.58rem', textTransform: 'uppercase', letterSpacing: '.2em', color: 'var(--e-gold)', fontWeight: 700, fontFamily: 'var(--e-sans)', marginBottom: 3 }}>
                            Bộ Lọc Nâng Cao
                        </div>
                        <h3 style={{ fontFamily: 'var(--e-serif)', fontSize: '1.2rem', fontWeight: 500, color: 'var(--e-charcoal)', margin: 0 }}>
                            Tinh Chỉnh Kết Quả
                        </h3>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        {activeCount > 0 && (
                            <button onClick={reset} style={{
                                background: 'none', border: '1px solid var(--e-beige)', padding: '6px 14px',
                                fontSize: '0.68rem', fontWeight: 600, letterSpacing: '.08em', textTransform: 'uppercase',
                                color: 'var(--e-muted)', cursor: 'pointer', fontFamily: 'var(--e-sans)',
                                transition: 'all .15s',
                            }}
                                onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--e-charcoal)'; e.currentTarget.style.color = 'var(--e-charcoal)'; }}
                                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--e-beige)'; e.currentTarget.style.color = 'var(--e-muted)'; }}
                            >
                                Đặt Lại {activeCount > 0 ? `(${activeCount})` : ''}
                            </button>
                        )}
                        <button onClick={() => setDrawerOpen(false)} style={{ background: 'var(--e-cream)', border: '1px solid var(--e-beige)', width: 36, height: 36, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', transition: 'all .15s', color: 'var(--e-charcoal)' }}
                            onMouseEnter={e => e.currentTarget.style.background = 'var(--e-beige)'}
                            onMouseLeave={e => e.currentTarget.style.background = 'var(--e-cream)'}
                        >
                            <X size={16} />
                        </button>
                    </div>
                </div>

                {/* Drawer body — scrollable */}
                <div style={{ flex: 1, overflowY: 'auto', padding: '2rem 2rem 1rem' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 3rem' }}>

                        {/* Left column */}
                        <div>
                            {/* Property type */}
                            <DrawerSection title="Loại Bất Động Sản">
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                                    {PROPERTY_TYPES.map(pt => (
                                        <Chip
                                            key={pt.value}
                                            label={pt.label}
                                            active={types.includes(pt.value)}
                                            onClick={() => toggleArr(types, pt.value, setTypes)}
                                        />
                                    ))}
                                </div>
                            </DrawerSection>

                            {/* Bedrooms */}
                            <DrawerSection title="Số Phòng Ngủ">
                                <div style={{ display: 'flex', gap: 8 }}>
                                    {BEDROOM_OPTS.map(b => (
                                        <Chip
                                            key={b}
                                            label={b}
                                            active={bedrooms.includes(b)}
                                            onClick={() => toggleArr(bedrooms, b, setBedrooms)}
                                        />
                                    ))}
                                </div>
                            </DrawerSection>

                            {/* Bathrooms */}
                            <DrawerSection title="Số Phòng Tắm">
                                <div style={{ display: 'flex', gap: 8 }}>
                                    {BATHROOM_OPTS.map(b => (
                                        <Chip
                                            key={b}
                                            label={b}
                                            active={bathrooms.includes(b)}
                                            onClick={() => toggleArr(bathrooms, b, setBathrooms)}
                                        />
                                    ))}
                                </div>
                            </DrawerSection>
                        </div>

                        {/* Right column */}
                        <div>
                            {/* Price range */}
                            <DrawerSection title={isRent ? 'Giá Thuê (Triệu/Tháng)' : 'Khoảng Giá (Tỷ Đồng)'}>
                                <DualRange
                                    marks={priceMarks}
                                    valueMin={priceMin}
                                    valueMax={priceMax}
                                    formatTick={fmtPrice}
                                    onChange={(a, b) => { setPriceMin(a); setPriceMax(b); }}
                                />
                            </DrawerSection>

                            {/* Area range */}
                            <DrawerSection title="Diện Tích (m²)">
                                <DualRange
                                    marks={AREA_MARKS}
                                    valueMin={areaMin}
                                    valueMax={areaMax}
                                    formatTick={fmtArea}
                                    onChange={(a, b) => { setAreaMin(a); setAreaMax(b); }}
                                />
                            </DrawerSection>
                        </div>
                    </div>
                </div>

                {/* Drawer footer */}
                <div style={{ padding: '1.2rem 2rem', borderTop: '1px solid var(--e-beige)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0, background: 'var(--e-white)' }}>
                    <div style={{ fontSize: '0.78rem', color: 'var(--e-muted)', fontFamily: 'var(--e-sans)' }}>
                        {activeCount > 0
                            ? <><span style={{ fontWeight: 700, color: 'var(--e-charcoal)' }}>{activeCount}</span> bộ lọc đang áp dụng</>
                            : 'Chưa có bộ lọc nào'}
                    </div>
                    <button onClick={handleSearch} style={{
                        display: 'inline-flex', alignItems: 'center', gap: 9,
                        padding: '13px 32px', background: 'var(--e-charcoal)', color: '#fff',
                        border: '1px solid var(--e-charcoal)', cursor: 'pointer',
                        fontFamily: 'var(--e-sans)', fontSize: '0.72rem', fontWeight: 700,
                        letterSpacing: '.14em', textTransform: 'uppercase', transition: 'all .2s',
                    }}
                        onMouseEnter={e => { e.currentTarget.style.background = 'var(--e-gold)'; e.currentTarget.style.borderColor = 'var(--e-gold)'; }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'var(--e-charcoal)'; e.currentTarget.style.borderColor = 'var(--e-charcoal)'; }}
                    >
                        <Search size={14} /> Áp Dụng & Tìm Kiếm
                    </button>
                </div>
            </div>

            <style>{`
                @keyframes ss-spin { to { transform: rotate(360deg); } }
                @media (max-width: 768px) {
                    .ss-drawer-grid { grid-template-columns: 1fr !important; }
                }
            `}</style>
        </>
    );
}