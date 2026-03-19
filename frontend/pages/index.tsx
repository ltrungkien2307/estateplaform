import type { GetServerSideProps } from 'next';
import { useEffect, useMemo, useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';

import { useScrollReveal } from '@/hooks/useScrollReveal';
import { ApiError } from '@/services/apiClient';
import { propertyService } from '@/services/propertyService';
import type { Property, PropertyFilters } from '@/types/property';

import LuxuryNavbar from '@/components/LuxuryNavbar';
import HeroSection from '@/components/HeroSection';
import MarqueeStrip from '@/components/MarqueeStrip';
import SearchSection from '@/components/SearchSection';
import type { SearchParams } from '@/components/SearchSection';
import FeaturedSection from '@/components/FeaturedSection';
import LuxuryListingCard from '@/components/LuxuryListingCard';
import VisionSection from '@/components/VisionSection';
import GallerySection from '@/components/GallerySection';
import LuxuryFooter from '@/components/LuxuryFooter';

/* ─────────────────────────────────────────────
   TYPE MAP  (SearchSection trả về value string)
───────────────────────────────────────────── */
const TYPE_MAP: Record<string, PropertyFilters['type']> = {
  apartment: 'apartment',
  villa: 'villa',
  house: 'house',
  studio: 'studio',
  office: 'office',
  land: 'house',       // fallback
  shophouse: 'office',
  penthouse: 'apartment',
};

/* ─────────────────────────────────────────────
   PRICE HELPERS  (SearchSection mới trả về số tỷ/triệu)
   - Mua bán: đơn vị TỶ  → nhân 1_000_000_000
   - Cho thuê: đơn vị TRIỆU/THÁNG → nhân 1_000_000
───────────────────────────────────────────── */
function priceToVND(val: number, isRent: boolean): number {
  return isRent ? val * 1_000_000 : val * 1_000_000_000;
}

/* ─────────────────────────────────────────────
   PAGE PROPS
───────────────────────────────────────────── */
interface HomePageProps {
  initialProperties: Property[];
  initialError: string | null;
}

function getErrorMessage(e: unknown): string {
  if (e instanceof ApiError || e instanceof Error) return e.message;
  return 'Không thể tải danh sách hiện tại.';
}

/* ─────────────────────────────────────────────
   PAGE
───────────────────────────────────────────── */
export default function HomePage({ initialProperties, initialError }: HomePageProps) {
  const router = useRouter();

  const [properties, setProperties] = useState<Property[]>(initialProperties);
  const [searchError, setSearchError] = useState<string | null>(initialError);
  const [searchLoading, setSearchLoading] = useState(false);
  const [listingKey, setListingKey] = useState(0);
  const [appliedFilters, setAppliedFilters] = useState<PropertyFilters>({});
  const [sortOrder, setSortOrder] = useState<'newest' | 'price-asc' | 'price-desc' | 'area'>('newest');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(initialProperties.length);
  const [totalPages, setTotalPages] = useState(1);
  const [activeTab, setActiveTab] = useState<string>('Mua Bán');

  const PER_PAGE = 8;

  useScrollReveal();
  useScrollReveal([listingKey]);

  const featuredProperties = useMemo(() => properties.slice(0, 3), [properties]);

  const hasActiveFilters = useMemo(
    () => Object.entries(appliedFilters).some(([k, v]) => k !== 'status' && v !== undefined && v !== ''),
    [appliedFilters]
  );

  function handlePostClick() {
    const token = typeof window !== 'undefined' ? localStorage.getItem('estate_manager_token') : null;
    router.push(token ? '/provider/properties/create' : '/auth/login?redirect=/provider/properties/create');
  }

  const getSortParam = (o: typeof sortOrder) => ({
    'price-asc': 'price',
    'price-desc': '-price',
    'area': '-area',
    'newest': '-createdAt',
  }[o]);

  const fetchProperties = async (
    filters: PropertyFilters = {},
    sort: typeof sortOrder = sortOrder,
    page = 1,
  ) => {
    setSearchLoading(true);
    setSearchError(null);
    try {
      const res = await propertyService.getAllProperties({
        ...filters,
        sort: getSortParam(sort),
        limit: PER_PAGE,
        page,
      });
      setProperties(res.data.properties);
      const total = (res as any).results ?? res.data.properties.length;
      setTotalCount(total);
      setTotalPages((res as any).totalPages ?? Math.ceil(total / PER_PAGE));
    } catch (err) {
      setSearchError(getErrorMessage(err));
      setProperties([]);
    } finally {
      setSearchLoading(false);
      setListingKey(k => k + 1);
    }
  };

  const handleSortChange = (s: typeof sortOrder) => {
    setSortOrder(s); setCurrentPage(1);
    fetchProperties(appliedFilters, s, 1);
  };

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    fetchProperties(appliedFilters, sortOrder, page);
    document.getElementById('listings')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  /* ── Search handler — nhận SearchParams mới từ SearchSection ── */
  async function handleSearch(params: SearchParams) {
    const isRent = params.tab === 'Cho Thuê';
    setActiveTab(params.tab);

    const filters: PropertyFilters = { status: 'approved' };

    // Location
    if (params.location.trim()) {
      filters.search = params.location.trim();
      filters.locationText = params.location.trim();
    }

    // Types — array, lấy phần tử đầu hoặc bỏ qua nếu rỗng
    if (params.types?.length > 0) {
      const mapped = TYPE_MAP[params.types[0]];
      if (mapped) filters.type = mapped;
    }

    // Price — SearchSection trả về số (tỷ hoặc triệu), convert sang VND
    const PRICE_MAX_RAW = isRent ? 100 : 50; // tối đa slider
    if (params.priceMin > 0) {
      filters.priceMin = priceToVND(params.priceMin, isRent);
    }
    if (params.priceMax < PRICE_MAX_RAW) {
      filters.priceMax = priceToVND(params.priceMax, isRent);
    }

    // Area — SearchSection trả về số m²
    if (params.areaMin > 0) filters.areaMin = params.areaMin;
    if (params.areaMax < 500) filters.areaMax = params.areaMax;

    // Bedrooms — lấy giá trị nhỏ nhất đã chọn
    if (params.bedrooms?.length > 0) {
      const nums = params.bedrooms
        .map(b => parseInt(b, 10))
        .filter(n => !isNaN(n));
      if (nums.length > 0) filters.bedrooms = Math.min(...nums);
    }

    // Bathrooms
    if (params.bathrooms?.length > 0) {
      const nums = params.bathrooms
        .map(b => parseInt(b, 10))
        .filter(n => !isNaN(n));
      if (nums.length > 0) filters.bathrooms = Math.min(...nums);
    }

    setAppliedFilters(filters);
    setCurrentPage(1);
    await fetchProperties(filters, sortOrder, 1);

    // Scroll xuống listings
    setTimeout(() => {
      document.getElementById('listings')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  }

  return (
    <>
      <Head>
        <title>Estoria — Bất Động Sản Cao Cấp Việt Nam</title>
        <meta name="description" content="Khám phá hàng nghìn bất động sản cao cấp được tuyển chọn kỹ lưỡng tại Việt Nam." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </Head>

      <div className="estoria relative min-h-screen">
        <LuxuryNavbar onPostClick={handlePostClick} />

        {/* 01 — Hero */}
        <HeroSection totalListings={totalCount} />

        {/* Marquee */}
        <MarqueeStrip />

        {/* Search */}
        <SearchSection onSearch={handleSearch} loading={searchLoading} />

        {/* 02 — Featured */}
        <FeaturedSection properties={featuredProperties} />

        {/* 03 — Listings */}
        <section className="e-listings e-section" id="listings">
          <div className="e-listings-header e-reveal">
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: '2rem' }}>
              <span style={{
                fontFamily: 'var(--e-serif)', fontSize: 'clamp(4rem,7vw,7rem)',
                fontWeight: 200, color: 'var(--e-beige)', lineHeight: 1,
                letterSpacing: '-0.04em', userSelect: 'none',
              }}>03</span>
              <div>
                <div className="e-section-label">Danh Sách</div>
                <h2 className="e-section-title">
                  {hasActiveFilters ? 'Kết Quả Tìm Kiếm' : <><em>Mới</em> Đăng Gần Đây</>}
                </h2>
                <p style={{ fontSize: '0.8rem', color: 'var(--e-muted)', marginTop: '0.3rem' }}>
                  {totalCount.toLocaleString('vi-VN')} bất động sản
                  {searchLoading ? ' (đang tải…)' : ''}
                </p>
              </div>
            </div>

            <div className="e-sort-bar">
              <span className="e-sort-label">Sắp xếp:</span>
              <select
                className="e-sort-select"
                value={sortOrder}
                onChange={e => handleSortChange(e.target.value as typeof sortOrder)}
              >
                <option value="newest">Mới nhất</option>
                <option value="price-asc">Giá tăng dần</option>
                <option value="price-desc">Giá giảm dần</option>
                <option value="area">Diện tích</option>
              </select>
            </div>
          </div>

          {searchError && (
            <div style={{ border: '1px solid #f5c6c6', background: '#fdf2f2', padding: '12px 16px', fontSize: '0.85rem', color: '#c0392b', marginBottom: '1.5rem' }}>
              {searchError}
            </div>
          )}

          {searchLoading ? (
            <div className="e-listings-grid">
              {Array.from({ length: PER_PAGE }).map((_, i) => (
                <div key={i} style={{ height: 380, background: 'var(--e-beige)', borderRadius: 4, opacity: 0.4, animation: 'pulse 1.5s ease-in-out infinite' }} />
              ))}
            </div>
          ) : properties.length > 0 ? (
            <div key={listingKey} className="e-listings-grid e-stagger">
              {properties.map(p => <LuxuryListingCard key={p._id} property={p} />)}
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '4rem 2rem', background: 'var(--e-white)', border: '1px solid var(--e-beige)' }}>
              <p style={{ fontFamily: 'var(--e-serif)', fontSize: '1.4rem', fontWeight: 300, color: 'var(--e-charcoal)', marginBottom: '0.5rem' }}>
                Không tìm thấy bất động sản
              </p>
              <p style={{ fontSize: '0.85rem', color: 'var(--e-muted)' }}>
                Hãy thử mở rộng bộ lọc hoặc tìm kiếm với từ khoá khác.
              </p>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && !searchLoading && (
            <div className="e-pagination e-reveal">
              {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => i + 1).map(page => (
                <button key={page} className={`e-page-btn${page === currentPage ? ' active' : ''}`} onClick={() => handlePageChange(page)}>
                  <span>{page}</span>
                </button>
              ))}
              {totalPages > 5 && (
                <>
                  <button className="e-page-btn" style={{ width: 'auto', padding: '0 8px' }}>…</button>
                  <button className="e-page-btn" onClick={() => handlePageChange(totalPages)}><span>{totalPages}</span></button>
                </>
              )}
              {currentPage < totalPages && (
                <button className="e-page-btn" style={{ width: 'auto', padding: '0 14px' }} onClick={() => handlePageChange(currentPage + 1)}>
                  <span>Tiếp →</span>
                </button>
              )}
            </div>
          )}
        </section>

        {/* 04 — Vision */}
        <VisionSection />

        {/* 05 — Gallery */}
        <GallerySection />

        <LuxuryFooter />
      </div>
    </>
  );
}

/* ─── SSR ─── */
export const getServerSideProps: GetServerSideProps<HomePageProps> = async () => {
  try {
    const res = await propertyService.getAllProperties({
      sort: '-createdAt', limit: 8, page: 1, status: 'approved',
    });
    return { props: { initialProperties: res.data.properties, initialError: null } };
  } catch {
    return { props: { initialProperties: [], initialError: null } };
  }
};