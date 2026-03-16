import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Layout from "@/components/Layout";
import propertyService from "@/services/propertyService";
import { useAuth } from "@/contexts/AuthContext";
import type { Property } from "@/types/property";
import Link from "next/link";

export default function ProviderProperties() {
  const router = useRouter();
  const { user, isAuthLoading } = useAuth();
  const [properties, setProperties] = useState<Property[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<"all" | "pending" | "approved" | "rejected">("all");

  useEffect(() => {
    const loadProperties = async () => {
      try {
        if (!user || user.role !== "provider") {
          router.push("/");
          return;
        }

        const response = await propertyService.getAllProperties({ limit: 100 });
        setProperties(response.data.properties);
      } catch (error) {
        console.error("Error loading properties:", error);
      } finally {
        setLoading(false);
      }
    };

    if (!isAuthLoading) {
      loadProperties();
    }
  }, [router, user, isAuthLoading]);

  const filteredProperties = properties.filter((p) => (filter === "all" ? true : p.status === filter));

  const handleDelete = async (id: string) => {
    if (!confirm("Bạn có chắc chắn muốn xóa bất động sản này?")) return;

    try {
      await propertyService.deleteProperty(id);
      setProperties(properties.filter((p) => p._id !== id));
      alert("Xóa bất động sản thành công");
    } catch (error) {
      console.error("Error deleting property:", error);
      alert("Lỗi khi xóa bất động sản");
    }
  };

  if (loading) {
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
      <div className="container mx-auto px-4 py-8 max-w-6xl">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Quản lý bất động sản</h1>
          <Link
            href="/provider/properties/create"
            className="bg-blue-600 text-white px-6 py-2 rounded-lg font-semibold hover:bg-blue-700 transition"
          >
            + Tạo mới
          </Link>
        </div>

        {/* Filters */}
        <div className="flex gap-2 mb-6">
          {["all", "pending", "approved", "rejected"].map((status) => (
            <button
              key={status}
              onClick={() => setFilter(status as typeof filter)}
              className={`px-4 py-2 rounded-lg font-medium transition ${
                filter === status
                  ? "bg-blue-600 text-white"
                  : "bg-gray-200 text-gray-900 hover:bg-gray-300"
              }`}
            >
              {status === "all" && "Tất cả"}
              {status === "pending" && "Đang chờ"}
              {status === "approved" && "Đã phê duyệt"}
              {status === "rejected" && "Bị từ chối"}
            </button>
          ))}
        </div>

        {/* Properties List */}
        {filteredProperties.length > 0 ? (
          <div className="space-y-3">
            {filteredProperties.map((property) => (
              <div
                key={property._id}
                className="bg-white rounded-lg shadow-md p-4 border border-gray-200 hover:shadow-lg transition"
              >
                <div className="flex justify-between items-start gap-4">
                  <div className="flex-1">
                    <h3 className="font-bold text-lg text-gray-900 mb-1">{property.title}</h3>
                    <p className="text-sm text-gray-600 mb-2">{property.address}</p>
                    <div className="flex gap-4 text-sm text-gray-700">
                      <span>💰 {new Intl.NumberFormat("vi-VN", {
                          style: "currency",
                          currency: "VND",
                        }).format(property.price)}</span>
                      <span>📐 {property.area} m²</span>
                      <span>🛏️ {property.bedrooms || 0} phòng</span>
                    </div>
                  </div>

                  <div className="text-right">
                    <span
                      className={`inline-block px-3 py-1 rounded-full text-sm font-semibold mb-3 ${
                        property.status === "approved"
                          ? "bg-green-100 text-green-700"
                          : property.status === "pending"
                            ? "bg-yellow-100 text-yellow-700"
                            : "bg-red-100 text-red-700"
                      }`}
                    >
                      {property.status === "approved" && "✓ Đã phê duyệt"}
                      {property.status === "pending" && "⏳ Đang chờ"}
                      {property.status === "rejected" && "✗ Bị từ chối"}
                    </span>

                    <div className="flex gap-2 justify-end">
                      <Link
                        href={`/properties/${property._id}`}
                        className="text-blue-600 hover:text-blue-800 font-semibold text-sm"
                      >
                        Xem
                      </Link>
                      <Link
                        href={`/provider/properties/${property._id}/edit`}
                        className="text-green-600 hover:text-green-800 font-semibold text-sm"
                      >
                        Sửa
                      </Link>
                      <button
                        onClick={() => handleDelete(property._id)}
                        className="text-red-600 hover:text-red-800 font-semibold text-sm"
                      >
                        Xóa
                      </button>
                    </div>
                  </div>
                </div>

                {property.rejectionReason && property.status === "rejected" && (
                  <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded">
                    <p className="text-sm text-red-700">
                      <span className="font-semibold">Lý do từ chối:</span> {property.rejectionReason}
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <p className="text-gray-600 mb-4">
              Không có bất động sản {filter !== "all" ? `ở trạng thái '${filter}'` : ""}
            </p>
            <Link
              href="/provider/properties/create"
              className="inline-block bg-blue-600 text-white px-6 py-2 rounded-lg font-semibold hover:bg-blue-700 transition"
            >
              Tạo bất động sản đầu tiên
            </Link>
          </div>
        )}
      </div>
    </Layout>
  );
}
