import React, { useState } from "react";
import Image from "next/image";
import type { Property, PropertyType } from "@/types/property";

interface PropertyFormData {
  title: string;
  description: string;
  price: number;
  address: string;
  location: {
    type: "Point";
    coordinates: [number, number];
  };
  type: PropertyType;
  bedrooms?: number;
  bathrooms?: number;
  area?: number;
  furnished: boolean;
  yearBuilt?: number;
  amenities: string[];
}

interface PropertyFormProps {
  initialData?: Property;
  onSubmit: (data: PropertyFormData) => Promise<void>;
  isLoading?: boolean;
}

const PROPERTY_TYPES: PropertyType[] = ["apartment", "house", "villa", "studio", "office"];

const AMENITIES_OPTIONS = [
  "Parking",
  "Balcony",
  "Garden",
  "Pool",
  "Gym",
  "Security",
  "WiFi",
  "Air Conditioning",
  "Kitchen",
  "Washing Machine",
];

export default function PropertyForm({ initialData, onSubmit, isLoading = false }: PropertyFormProps) {
  const [formData, setFormData] = useState<PropertyFormData>(
    initialData || {
      title: "",
      description: "",
      price: 0,
      address: "",
      location: { type: "Point", coordinates: [0, 0] },
      type: "apartment",
      bedrooms: 1,
      bathrooms: 1,
      area: 0,
      furnished: false,
      yearBuilt: new Date().getFullYear(),
      amenities: [],
    }
  );

  const [errors, setErrors] = useState<Partial<Record<keyof PropertyFormData, string>>>({});

  const validateForm = () => {
    const newErrors: typeof errors = {};

    if (!formData.title.trim()) newErrors.title = "Tiêu đề bắt buộc";
    if (!formData.description.trim()) newErrors.description = "Mô tả bắt buộc";
    if (formData.price < 0) newErrors.price = "Giá phải dương";
    if (!formData.address.trim()) newErrors.address = "Địa chỉ bắt buộc";
    if (formData.location.coordinates[0] === 0 && formData.location.coordinates[1] === 0) {
      newErrors.location = "Vui lòng chọn vị trí trên bản đồ";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateForm()) return;
    await onSubmit(formData);
  };

  const handleAmenityChange = (amenity: string) => {
    setFormData((prev) => ({
      ...prev,
      amenities: prev.amenities.includes(amenity)
        ? prev.amenities.filter((a) => a !== amenity)
        : [...prev.amenities, amenity],
    }));
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Title */}
      <div>
        <label className="block text-sm font-medium text-text-secondary mb-2">Tiêu đề</label>
        <span className={`glass-input-wrapper ${errors.title ? "border-accent focus-within:border-accent" : ""}`}>
          <input
            type="text"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            className="glass-input"
            placeholder="Nhập tiêu đề bất động sản"
          />
        </span>
        {errors.title && <p className="text-accent text-sm mt-1.5">{errors.title}</p>}
      </div>

      {/* Description */}
      <div>
        <label className="block text-sm font-medium text-text-secondary mb-2">Mô tả</label>
        <span className={`glass-input-wrapper block p-0 overflow-hidden ${errors.description ? "border-accent focus-within:border-accent" : ""}`}>
          <textarea
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            rows={5}
            className="w-full border-none bg-transparent text-sm text-text-primary outline-none placeholder:text-text-secondary p-3 resize-y"
            placeholder="Mô tả chi tiết về bất động sản"
          />
        </span>
        {errors.description && <p className="text-accent text-sm mt-1.5">{errors.description}</p>}
      </div>

      {/* Price */}
      <div>
        <label className="block text-sm font-medium text-text-secondary mb-2">Giá (₫)</label>
        <span className={`glass-input-wrapper ${errors.price ? "border-accent focus-within:border-accent" : ""}`}>
          <input
            type="number"
            value={formData.price}
            onChange={(e) => setFormData({ ...formData, price: Number(e.target.value) })}
            className="glass-input"
            placeholder="0"
          />
        </span>
        {errors.price && <p className="text-accent text-sm mt-1.5">{errors.price}</p>}
      </div>

      {/* Address */}
      <div>
        <label className="block text-sm font-medium text-text-secondary mb-2">Địa chỉ</label>
        <span className={`glass-input-wrapper ${errors.address ? "border-accent focus-within:border-accent" : ""}`}>
          <input
            type="text"
            value={formData.address}
            onChange={(e) => setFormData({ ...formData, address: e.target.value })}
            className="glass-input"
            placeholder="Nhập địa chỉ đầy đủ"
          />
        </span>
        {errors.address && <p className="text-accent text-sm mt-1.5">{errors.address}</p>}
      </div>

      {/* Type */}
      <div>
        <label className="block text-sm font-medium text-text-secondary mb-2">Loại bất động sản</label>
        <span className="glass-input-wrapper">
          <select
            value={formData.type}
            onChange={(e) => setFormData({ ...formData, type: e.target.value as PropertyType })}
            className="glass-input"
          >
            {PROPERTY_TYPES.map((type) => (
              <option key={type} value={type}>
                {type === "apartment" && "Căn hộ"}
                {type === "house" && "Nhà riêng"}
                {type === "villa" && "Biệt thự"}
                {type === "studio" && "Studio"}
                {type === "office" && "Văn phòng"}
              </option>
            ))}
          </select>
        </span>
      </div>

      {/* Bedrooms, Bathrooms, Area */}
      <div className="grid grid-cols-3 gap-4">
        <div>
          <label className="block text-sm font-medium text-text-secondary mb-2">Phòng ngủ</label>
          <span className="glass-input-wrapper">
            <input
              type="number"
              value={formData.bedrooms || 0}
              onChange={(e) => setFormData({ ...formData, bedrooms: Number(e.target.value) })}
              className="glass-input"
              min="0"
            />
          </span>
        </div>

        <div>
          <label className="block text-sm font-medium text-text-secondary mb-2">Phòng tắm</label>
          <span className="glass-input-wrapper">
            <input
              type="number"
              value={formData.bathrooms || 0}
              onChange={(e) => setFormData({ ...formData, bathrooms: Number(e.target.value) })}
              className="glass-input"
              min="0"
            />
          </span>
        </div>

        <div>
          <label className="block text-sm font-medium text-text-secondary mb-2">Diện tích (m²)</label>
          <span className="glass-input-wrapper">
            <input
              type="number"
              value={formData.area || 0}
              onChange={(e) => setFormData({ ...formData, area: Number(e.target.value) })}
              className="glass-input"
              min="0"
            />
          </span>
        </div>
      </div>

      {/* Furnished */}
      <div className="flex items-center">
        <input
          type="checkbox"
          id="furnished"
          checked={formData.furnished}
          onChange={(e) => setFormData({ ...formData, furnished: e.target.checked })}
          className="w-4 h-4 rounded border-boundary text-primary-dark focus:ring-primary-light"
        />
        <label htmlFor="furnished" className="ml-2 block text-sm font-medium text-text-secondary cursor-pointer">
          Có nội thất
        </label>
      </div>

      {/* Year Built */}
      <div>
        <label className="block text-sm font-medium text-text-secondary mb-2">Năm xây dựng</label>
        <span className="glass-input-wrapper w-1/3">
          <input
            type="number"
            value={formData.yearBuilt || new Date().getFullYear()}
            onChange={(e) => setFormData({ ...formData, yearBuilt: Number(e.target.value) })}
            className="glass-input"
            min="1900"
            max={new Date().getFullYear()}
          />
        </span>
      </div>

      {/* Amenities */}
      <div>
        <label className="block text-sm font-medium text-text-secondary mb-3">Tiện ích</label>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 p-4 rounded-xl border border-boundary bg-surface shadow-sm">
          {AMENITIES_OPTIONS.map((amenity) => (
            <div key={amenity} className="flex items-center">
              <input
                type="checkbox"
                id={amenity}
                checked={formData.amenities.includes(amenity)}
                onChange={() => handleAmenityChange(amenity)}
                className="w-4 h-4 rounded border-boundary text-primary-dark focus:ring-primary-light"
              />
              <label htmlFor={amenity} className="ml-2 block text-sm text-text-primary cursor-pointer">
                {amenity}
              </label>
            </div>
          ))}
        </div>
      </div>

      {/* Submit Button */}
      <div className="pt-2">
        <button
          type="submit"
          disabled={isLoading}
          className="glass-button-primary w-full justify-center py-3 text-base"
        >
          {isLoading ? "Đang lưu..." : initialData ? "Cập nhật bất động sản" : "Tạo bất động sản"}
        </button>
      </div>
    </form>
  );
}
