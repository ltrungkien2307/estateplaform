import type { GetServerSideProps } from "next";
import { ArrowRight, Compass, LoaderCircle, ShieldCheck, Sparkles } from "lucide-react";
import AdvancedSearchBar from "@/components/AdvancedSearchBar";
import Layout from "@/components/Layout";
import ListingCard from "@/components/ListingCard";
import { useAuth } from "@/contexts/AuthContext";
import { ApiError } from "@/services/apiClient";
import { propertyService } from "@/services/propertyService";
import type { Property, PropertyFilters } from "@/types/property";
import { useMemo, useState } from "react";

interface HomePageProps {
  initialProperties: Property[];
  initialError: string | null;
}

function getErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "Unable to load listings right now.";
}

export default function HomePage({ initialProperties, initialError }: HomePageProps) {
  const { user } = useAuth();
  const [properties, setProperties] = useState<Property[]>(initialProperties);
  const [searchError, setSearchError] = useState<string | null>(initialError);
  const [searchLoading, setSearchLoading] = useState(false);
  const [appliedFilters, setAppliedFilters] = useState<PropertyFilters>({});

  const featuredProperties = useMemo(() => properties.slice(0, 3), [properties]);

  const hasActiveFilters = useMemo(
    () => Object.values(appliedFilters).some((value) => value !== undefined && value !== ""),
    [appliedFilters]
  );

  return (
    <Layout>
      <section className="glass-panel relative overflow-hidden px-4 py-8 sm:px-10 sm:py-10">
        <div className="absolute right-0 top-0 h-32 w-32 rounded-full bg-indigo-300/20 blur-3xl sm:h-44 sm:w-44" />
        <div className="absolute bottom-0 left-1/3 h-32 w-32 rounded-full bg-sky-200/20 blur-3xl sm:h-40 sm:w-40" />
        <div className="relative space-y-4 sm:space-y-6">
          <span className="inline-flex items-center gap-2 rounded-full border border-white/70 bg-white/70 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-700 sm:px-4 sm:py-2">
            <Sparkles size={14} />
            EstateManager Platform
          </span>
          <h1 className="max-w-3xl text-2xl font-semibold leading-tight text-slate-900 sm:text-3xl md:text-5xl">
            Find the right property with precise filters and fast detail views.
          </h1>
          <p className="max-w-2xl text-sm leading-relaxed text-slate-600 sm:text-base md:text-lg">
            Search, compare, and inspect listings using the advanced filter system connected to the live
            EstateManager API.
          </p>
          <div className="grid gap-2 sm:gap-3 grid-cols-1 sm:grid-cols-3">
            <div className="stat-card">
              <Compass size={18} />
              <div>
                <p className="text-xs text-slate-500">Listings Available</p>
                <p className="text-lg font-semibold text-slate-900">{properties.length}</p>
              </div>
            </div>
            <div className="stat-card">
              <ShieldCheck size={18} />
              <div>
                <p className="text-xs text-slate-500">Verified Providers</p>
                <p className="text-lg font-semibold text-slate-900">Growing Daily</p>
              </div>
            </div>
            <div className="stat-card">
              <ArrowRight size={18} />
              <div>
                <p className="text-xs text-slate-500">Current Session</p>
                <p className="text-lg font-semibold text-slate-900">
                  {user ? `${user.name} (${user.role})` : "Guest"}
                </p>
              </div>
            </div>
          </div>

          <AdvancedSearchBar
            onResults={(nextProperties, filters) => {
              setProperties(nextProperties);
              setAppliedFilters(filters);
              setSearchError(null);
            }}
            onError={setSearchError}
            onLoadingChange={setSearchLoading}
          />
        </div>
      </section>

      <section id="featured" className="mt-6 sm:mt-8 space-y-3 sm:space-y-4">
        <div className="flex flex-col sm:flex-row flex-wrap items-start sm:items-end justify-between gap-2 sm:gap-3">
          <div>
            <p className="text-xs sm:text-sm font-medium text-slate-500">Featured Properties</p>
            <h2 className="text-xl sm:text-2xl font-semibold text-slate-900">Highlighted picks from current results</h2>
          </div>
        </div>

        {featuredProperties.length > 0 ? (
          <div className="grid gap-3 sm:gap-4 grid-cols-1 md:grid-cols-3">
            {featuredProperties.map((property) => (
              <ListingCard key={property._id} property={property} />
            ))}
          </div>
        ) : (
          <div className="glass-panel text-center">
            <p className="text-sm text-slate-600">No featured properties match the active filters yet.</p>
          </div>
        )}
      </section>

      <section id="listings" className="mt-6 sm:mt-8 space-y-3 sm:space-y-4">
        <div className="flex flex-col sm:flex-row flex-wrap items-start sm:items-center justify-between gap-2 sm:gap-3">
          <div>
            <p className="text-xs sm:text-sm font-medium text-slate-500">Latest Listings</p>
            <h3 className="text-xl sm:text-2xl font-semibold text-slate-900">
              {hasActiveFilters ? "Filtered Results" : "Most Recent Properties"}
            </h3>
            <p className="mt-1 text-xs sm:text-sm text-slate-600">
              {properties.length} properties found
              {searchLoading ? " (updating...)" : ""}
            </p>
          </div>
          {searchLoading ? <LoaderCircle size={18} className="animate-spin text-slate-500" /> : null}
        </div>

        {searchError ? (
          <div className="rounded-2xl border border-rose-200 bg-rose-50 px-3 py-2 sm:px-4 sm:py-3 text-xs sm:text-sm text-rose-600">
            {searchError}
          </div>
        ) : null}

        {properties.length > 0 ? (
          <div className="grid gap-3 sm:gap-4 grid-cols-1 sm:grid-cols-2 xl:grid-cols-3">
            {properties.map((property) => (
              <ListingCard key={property._id} property={property} />
            ))}
          </div>
        ) : (
          <div className="glass-panel text-center">
            <h4 className="text-lg font-semibold text-slate-900">No Listings Found</h4>
            <p className="mt-2 text-sm text-slate-600">
              Try widening your filters or reset to browse the latest approved properties.
            </p>
          </div>
        )}
      </section>
    </Layout>
  );
}

export const getServerSideProps: GetServerSideProps<HomePageProps> = async () => {
  try {
    const response = await propertyService.getAllProperties({
      sort: "-createdAt",
      limit: 24,
    });

    return {
      props: {
        initialProperties: response.data.properties,
        initialError: null,
      },
    };
  } catch (error) {
    return {
      props: {
        initialProperties: [],
        initialError: getErrorMessage(error),
      },
    };
  }
};

