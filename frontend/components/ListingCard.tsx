import Link from "next/link";
import Image from "next/image";
import {
  Bath,
  BedDouble,
  Building2,
  MapPin,
  MoveRight,
  Ruler,
} from "lucide-react";
import type { Property } from "@/types/property";

interface ListingCardProps {
  property: Property;
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

export default function ListingCard({ property }: ListingCardProps) {
  const mainImage = property.images?.[0];

  return (
    <article className="listing-card h-full rounded-3xl border border-slate-200 p-3 sm:p-4 backdrop-blur-md" style={{ backgroundColor: "rgba(255, 255, 255, 0.65)", borderColor: "rgba(255, 255, 255, 0.6)" }}>
      <div className="relative mb-3 sm:mb-4 overflow-hidden rounded-2xl">
        {mainImage ? (
          <Image
            src={mainImage}
            alt={property.title}
            width={640}
            height={360}
            unoptimized
            className="image-zoom h-40 sm:h-48 w-full object-cover"
          />
        ) : (
          <div className="flex h-40 sm:h-48 w-full items-center justify-center bg-gradient-to-br from-slate-200 to-slate-100 text-slate-600">
            <Building2 size={22} />
          </div>
        )}
        <span className="absolute left-2 top-2 sm:left-3 sm:top-3 rounded-full border border-slate-200 px-2 sm:px-3 py-0.5 sm:py-1 text-xs font-semibold uppercase tracking-wide text-slate-900 shadow-sm backdrop-blur-md" style={{ backgroundColor: "rgba(255, 255, 255, 0.65)" }}>
          {property.type}
        </span>
      </div>

      <div className="flex h-[calc(100%-9.5rem)] sm:h-[calc(100%-13rem)] flex-col">
        <h3 className="line-clamp-2 text-base sm:text-lg font-semibold text-slate-900">{property.title}</h3>
        <p className="mt-1 sm:mt-2 text-lg sm:text-xl font-bold text-indigo-800">{formatCurrency(property.price)}</p>

        <p className="mt-1 sm:mt-2 inline-flex items-start gap-1.5 sm:gap-2 text-xs sm:text-sm text-slate-600">
          <MapPin size={15} className="mt-0.5 shrink-0" />
          <span className="line-clamp-2">{property.address}</span>
        </p>

        <div className="mt-2 sm:mt-4 grid grid-cols-3 gap-1 sm:gap-2 text-xs text-slate-600">
          <div className="flex items-center gap-1 rounded-xl border border-slate-200 px-1.5 sm:px-2 py-1.5 sm:py-2 shadow-sm" style={{ backgroundColor: "rgba(255, 255, 255, 0.65)" }}>
            <BedDouble size={14} />
            <span className="text-xs">{formatNumber(property.bedrooms)}</span>
          </div>
          <div className="flex items-center gap-1 rounded-xl border border-slate-200 px-1.5 sm:px-2 py-1.5 sm:py-2 shadow-sm" style={{ backgroundColor: "rgba(255, 255, 255, 0.65)" }}>
            <Bath size={14} />
            <span className="text-xs">{formatNumber(property.bathrooms)}</span>
          </div>
          <div className="flex items-center gap-1 rounded-xl border border-slate-200 px-1.5 sm:px-2 py-1.5 sm:py-2 shadow-sm" style={{ backgroundColor: "rgba(255, 255, 255, 0.65)" }}>
            <Ruler size={14} />
            <span className="text-xs">{formatNumber(property.area)} m2</span>
          </div>
        </div>

        <div className="mt-auto pt-2 sm:pt-4">
          <Link href={`/properties/${property._id}`} className="glass-button-primary w-full justify-center text-xs sm:text-sm">
            View Details
            <MoveRight size={16} />
          </Link>
        </div>
      </div>
    </article>
  );
}
