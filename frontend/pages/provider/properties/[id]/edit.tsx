import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import Layout from "@/components/Layout";
import PropertyForm from "@/components/PropertyForm";
import propertyService from "@/services/propertyService";
import { useAuth } from "@/contexts/AuthContext";
import type { Property } from "@/types/property";

interface PropertyFormData {
  title: string;
  description: string;
  price: number;
  address: string;
  location: {
    type: "Point";
    coordinates: [number, number];
  };
  type: "apartment" | "house" | "villa" | "studio" | "office";
  bedrooms?: number;
  bathrooms?: number;
  area?: number;
  furnished: boolean;
  yearBuilt?: number;
  amenities: string[];
}

export default function EditProperty() {
  const router = useRouter();
  const { id } = router.query;
  const { user, isAuthLoading } = useAuth();
  const [property, setProperty] = useState<Property | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    const loadProperty = async () => {
      try {
        if (!user || user.role !== "provider") {
          router.push("/");
          return;
        }

        if (id && typeof id === "string") {
          const prop = await propertyService.getPropertyById(id);
          setProperty(prop);
        }
      } catch (error) {
        console.error("Error loading property:", error);
        router.push("/provider/properties");
      } finally {
        setInitialized(true);
      }
    };

    if (router.isReady && !isAuthLoading) {
      loadProperty();
    }
  }, [router.isReady, id, router, user, isAuthLoading]);

  const handleSubmit = async (data: PropertyFormData) => {
    if (!property) return;

    try {
      setIsLoading(true);
      await propertyService.updateProperty(property._id, data);
      alert("Cập nhật bất động sản thành công!");
      router.push("/provider/properties");
    } catch (error: any) {
      console.error("Error updating property:", error);
      alert(error.message || "Lỗi khi cập nhật bất động sản");
    } finally {
      setIsLoading(false);
    }
  };

  if (!initialized || !property) {
    return (
      <Layout>
        <div className="flex justify-center items-center min-h-screen">
          <div className="text-center">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-600"></div>
            <p className="mt-4 text-gray-700">Đang tải...</p>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8 max-w-2xl">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Chỉnh sửa bất động sản</h1>
        <p className="text-gray-600 mb-8">{property.title}</p>

        <div className="bg-white rounded-lg shadow-md p-6">
          <PropertyForm initialData={property} onSubmit={handleSubmit} isLoading={isLoading} />
        </div>
      </div>
    </Layout>
  );
}
