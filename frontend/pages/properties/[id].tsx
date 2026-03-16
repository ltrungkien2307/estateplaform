import { useState } from "react";
import type { FormEvent } from "react";
import type { GetServerSideProps } from "next";
import Link from "next/link";
import Image from "next/image";
import {
  Bath,
  BedDouble,
  Building2,
  CalendarClock,
  CheckCircle2,
  ChevronLeft,
  Mail,
  MapPin,
  Phone,
  Ruler,
  Send,
} from "lucide-react";
import Layout from "@/components/Layout";
import RecommendationCard from "@/components/RecommendationCard";
import { ApiError } from "@/services/apiClient";
import { propertyService } from "@/services/propertyService";
import type { Property, PropertyOwner } from "@/types/property";

interface PropertyDetailPageProps {
  property: Property | null;
  errorMessage: string | null;
  recommendations: Property[];
}

function formatCurrency(amount: number) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(amount);
}

function formatNumber(value?: number) {
  if (value === undefined || value === null) {
    return "N/A";
  }
  return new Intl.NumberFormat("en-US").format(value);
}

function isPopulatedOwner(owner: PropertyOwner): owner is Exclude<PropertyOwner, string> {
  return typeof owner !== "string";
}

function getErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.statusCode === 404) {
      return "Property not found or currently unavailable.";
    }
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "Unable to load property details right now.";
}

export default function PropertyDetailPage({ property, errorMessage, recommendations }: PropertyDetailPageProps) {
  const [activeImageIndex, setActiveImageIndex] = useState(0);
  const [contactSent, setContactSent] = useState(false);

  if (!property) {
    return (
      <Layout>
        <section className="glass-panel mx-auto max-w-3xl text-center">
          <h1 className="text-2xl font-semibold text-slate-900">Property Unavailable</h1>
          <p className="mt-2 text-sm text-slate-600">
            {errorMessage || "The property you are looking for does not exist."}
          </p>
          <Link href="/" className="glass-button-primary mt-6">
            <ChevronLeft size={16} />
            Back to Listings
          </Link>
        </section>
      </Layout>
    );
  }

  const images = property.images?.length ? property.images : [];
  const activeImage = images[activeImageIndex];
  const owner = isPopulatedOwner(property.ownerId) ? property.ownerId : null;

  const providerContactHref = owner?.email
    ? `mailto:${owner.email}?subject=${encodeURIComponent(`Inquiry about ${property.title}`)}`
    : "#contact-provider";

  const handleContactSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setContactSent(true);
  };

  return (
    <Layout>
      <div className="space-y-6">
        <Link href="/" className="glass-button">
          <ChevronLeft size={16} />
          Back to Listings
        </Link>

        <section className="glass-panel grid gap-6 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          <div className="space-y-3">
            <div className="overflow-hidden rounded-2xl border border-white/70 bg-white/70">
              {activeImage ? (
                <Image
                  src={activeImage}
                  alt={property.title}
                  width={1200}
                  height={800}
                  unoptimized
                  className="h-[320px] w-full object-cover sm:h-[420px]"
                />
              ) : (
                <div className="flex h-[320px] w-full items-center justify-center bg-gradient-to-br from-slate-200 to-slate-100 text-slate-500 sm:h-[420px]">
                  <Building2 size={26} />
                </div>
              )}
            </div>

            {images.length > 1 ? (
              <div className="grid grid-cols-4 gap-2">
                {images.map((imageUrl, index) => (
                  <button
                    key={`${imageUrl}-${index}`}
                    type="button"
                    onClick={() => setActiveImageIndex(index)}
                    className={`overflow-hidden rounded-xl border transition-all ${
                      index === activeImageIndex
                        ? "border-slate-900 shadow-lg shadow-slate-900/10"
                        : "border-white/70 hover:border-slate-400/70"
                    }`}
                  >
                    <Image
                      src={imageUrl}
                      alt={`${property.title} image ${index + 1}`}
                      width={220}
                      height={120}
                      unoptimized
                      className="h-20 w-full object-cover"
                    />
                  </button>
                ))}
              </div>
            ) : null}
          </div>

          <div className="space-y-4">
            <div className="space-y-2">
              <span className="inline-flex rounded-full border border-white/70 bg-white/80 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-slate-700">
                {property.type}
              </span>
              <h1 className="text-3xl font-semibold text-slate-900">{property.title}</h1>
              <p className="text-2xl font-bold text-slate-900">{formatCurrency(property.price)}</p>
              <p className="inline-flex items-start gap-2 text-sm text-slate-600">
                <MapPin size={15} className="mt-0.5 shrink-0" />
                <span>{property.address}</span>
              </p>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="rounded-xl bg-white/70 p-3 text-sm text-slate-700">
                <p className="inline-flex items-center gap-2 font-medium">
                  <BedDouble size={14} />
                  Bedrooms
                </p>
                <p className="mt-1 text-base font-semibold">{formatNumber(property.bedrooms)}</p>
              </div>
              <div className="rounded-xl bg-white/70 p-3 text-sm text-slate-700">
                <p className="inline-flex items-center gap-2 font-medium">
                  <Bath size={14} />
                  Bathrooms
                </p>
                <p className="mt-1 text-base font-semibold">{formatNumber(property.bathrooms)}</p>
              </div>
              <div className="rounded-xl bg-white/70 p-3 text-sm text-slate-700">
                <p className="inline-flex items-center gap-2 font-medium">
                  <Ruler size={14} />
                  Area
                </p>
                <p className="mt-1 text-base font-semibold">{formatNumber(property.area)} m2</p>
              </div>
              <div className="rounded-xl bg-white/70 p-3 text-sm text-slate-700">
                <p className="inline-flex items-center gap-2 font-medium">
                  <CalendarClock size={14} />
                  Year Built
                </p>
                <p className="mt-1 text-base font-semibold">{property.yearBuilt || "N/A"}</p>
              </div>
            </div>

            <div className="rounded-xl bg-white/70 p-4 text-sm text-slate-700">
              <p className="font-medium text-slate-900">Furnished</p>
              <p className="mt-1">{property.furnished ? "Yes" : "No"}</p>
            </div>

            <a href={providerContactHref} className="glass-button-primary w-full justify-center">
              <Send size={16} />
              Contact Provider
            </a>
          </div>
        </section>

        <section className="grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
          <article className="glass-panel">
            <h2 className="text-xl font-semibold text-slate-900">Property Description</h2>
            <p className="mt-3 whitespace-pre-line text-sm leading-relaxed text-slate-700">
              {property.description}
            </p>

            <h3 className="mt-6 text-lg font-semibold text-slate-900">Amenities</h3>
            {property.amenities?.length ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {property.amenities.map((amenity) => (
                  <span
                    key={amenity}
                    className="inline-flex items-center gap-1 rounded-full border border-white/70 bg-white/75 px-3 py-1 text-xs font-medium text-slate-700"
                  >
                    <CheckCircle2 size={12} />
                    {amenity}
                  </span>
                ))}
              </div>
            ) : (
              <p className="mt-2 text-sm text-slate-600">No amenities listed for this property.</p>
            )}

            <div className="mt-6 rounded-xl border border-white/70 bg-white/70 p-4">
              <h3 className="text-lg font-semibold text-slate-900">Location</h3>
              <p className="mt-2 text-sm text-slate-700">{property.address}</p>
              <p className="mt-1 text-xs text-slate-500">
                Coordinates: {property.location?.coordinates?.[1] ?? "N/A"},{" "}
                {property.location?.coordinates?.[0] ?? "N/A"}
              </p>
            </div>
          </article>

          <aside id="contact-provider" className="glass-panel h-fit">
            <h2 className="text-xl font-semibold text-slate-900">Provider Information</h2>
            {owner ? (
              <div className="mt-4 space-y-3 text-sm text-slate-700">
                <p className="font-semibold text-slate-900">{owner.name}</p>
                <p className="inline-flex items-center gap-2">
                  <Mail size={14} />
                  {owner.email}
                </p>
                {owner.phone ? (
                  <p className="inline-flex items-center gap-2">
                    <Phone size={14} />
                    {owner.phone}
                  </p>
                ) : (
                  <p className="text-slate-500">Phone number unavailable</p>
                )}
              </div>
            ) : (
              <p className="mt-3 text-sm text-slate-600">Provider details are currently unavailable.</p>
            )}

            <form onSubmit={handleContactSubmit} className="mt-6 space-y-3">
              <label className="flex flex-col gap-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
                Your Name
                <span className="glass-input-wrapper">
                  <input type="text" required className="glass-input" placeholder="Full name" />
                </span>
              </label>

              <label className="flex flex-col gap-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
                Your Email
                <span className="glass-input-wrapper">
                  <input type="email" required className="glass-input" placeholder="you@example.com" />
                </span>
              </label>

              <label className="flex flex-col gap-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
                Message
                <span className="glass-input-wrapper">
                  <textarea
                    required
                    rows={4}
                    className="glass-input resize-none"
                    placeholder="I would like to request a viewing..."
                  />
                </span>
              </label>

              <button type="submit" className="glass-button-primary w-full justify-center">
                Send Inquiry
                <Send size={14} />
              </button>
            </form>

            {contactSent ? (
              <p className="mt-3 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700">
                Inquiry submitted. Provider response integration can be connected in the next phase.
              </p>
            ) : null}
          </aside>
        </section>

        {/* Recommendations Section */}
        {recommendations.length > 0 && (
          <section className="glass-panel">
            <h2 className="mb-6 text-2xl font-bold text-slate-900">Similar Properties</h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {recommendations.map((rec) => (
                <Link key={rec._id} href={`/properties/${rec._id}`} passHref>
                  <RecommendationCard property={rec} />
                </Link>
              ))}
            </div>
          </section>
        )}
      </div>
    </Layout>
  );
}

export const getServerSideProps: GetServerSideProps<PropertyDetailPageProps> = async (context) => {
  const idParam = context.params?.id;
  const id = typeof idParam === "string" ? idParam : null;

  if (!id) {
    return {
      props: {
        property: null,
        errorMessage: "Invalid property id.",
        recommendations: [],
      },
    };
  }

  try {
    const property = await propertyService.getPropertyById(id);
    
    // Fetch recommendations
    let recommendations: Property[] = [];
    try {
      recommendations = await propertyService.getRecommendations(id);
    } catch (error) {
      console.error("Failed to fetch recommendations:", error);
      // Continue without recommendations if they fail to load
    }

    return {
      props: {
        property,
        errorMessage: null,
        recommendations,
      },
    };
  } catch (error) {
    return {
      props: {
        property: null,
        errorMessage: getErrorMessage(error),
        recommendations: [],
      },
    };
  }
};
