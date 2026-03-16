import { useRouter } from "next/router";
import Layout from "@/components/Layout";
import PropertyForm from "@/components/PropertyForm";
import propertyService from "@/services/propertyService";
import { useAuth } from "@/contexts/AuthContext";
import { useEffect, useState } from "react";
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

export default function CreateProperty() {
  const router = useRouter();
  const { user, isAuthLoading } = useAuth();
  const [existingProperty, setExistingProperty] = useState<Property | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    if (!isAuthLoading) {
      if (!user || user.role !== "provider") {
        router.push("/");
        return;
      }
      setInitialized(true);
    }
  }, [user, isAuthLoading, router]);

  const handleSubmit = async (data: PropertyFormData) => {
    try {
      setIsLoading(true);
      await propertyService.createProperty(data);
      alert("Tạo bất động sản thành công!");
      router.push("/provider/properties");
    } catch (error: any) {
      console.error("Error creating property:", error);
      alert(error.message || "Lỗi khi tạo bất động sản");
    } finally {
      setIsLoading(false);
    }
  };

  if (!initialized) {
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
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Tạo bất động sản mới</h1>
        <p className="text-gray-600 mb-8">
          Điền thông tin chi tiết về bất động sản của bạn. Bất động sản sẽ được xem xét trước khi công bố.
        </p>

        <div className="bg-white rounded-lg shadow-md p-6">
          <PropertyForm onSubmit={handleSubmit} isLoading={isLoading} />
        </div>
      </div>
    </Layout>
  );
}
