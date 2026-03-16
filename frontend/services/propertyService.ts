import { requestJson } from "@/services/apiClient";
import type { Property, PropertyFilters } from "@/types/property";

interface PropertiesResponse {
  status: string;
  results: number;
  data: {
    properties: Property[];
  };
}

interface PropertyResponse {
  status: string;
  data: {
    property: Property;
  };
}

function buildPropertiesQuery(filters?: PropertyFilters) {
  if (!filters) {
    return "";
  }

  const params = new URLSearchParams();

  if (filters.priceMin !== undefined) {
    params.set("price[gte]", String(filters.priceMin));
  }
  if (filters.priceMax !== undefined) {
    params.set("price[lte]", String(filters.priceMax));
  }
  if (filters.type) {
    params.set("type", filters.type);
  }
  if (filters.bedrooms !== undefined) {
    params.set("bedrooms", String(filters.bedrooms));
  }
  if (filters.bathrooms !== undefined) {
    params.set("bathrooms", String(filters.bathrooms));
  }
  if (filters.furnished !== undefined) {
    params.set("furnished", String(filters.furnished));
  }
  if (filters.sort) {
    params.set("sort", filters.sort);
  }
  if (filters.limit !== undefined) {
    params.set("limit", String(filters.limit));
  }
  if (filters.page !== undefined) {
    params.set("page", String(filters.page));
  }

  const queryString = params.toString();
  return queryString ? `?${queryString}` : "";
}

function applyClientSideKeywordFilter(properties: Property[], filters?: PropertyFilters) {
  if (!filters) {
    return properties;
  }

  const keyword = filters.search?.trim().toLowerCase();
  const location = filters.locationText?.trim().toLowerCase();

  if (!keyword && !location) {
    return properties;
  }

  return properties.filter((property) => {
    const haystack = [
      property.title,
      property.address,
      property.description,
      property.type,
      ...(property.amenities || []),
    ]
      .join(" ")
      .toLowerCase();

    const matchesKeyword = keyword ? haystack.includes(keyword) : true;
    const matchesLocation = location ? haystack.includes(location) : true;
    return matchesKeyword && matchesLocation;
  });
}

interface CreatePropertyPayload {
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
  amenities?: string[];
}

interface UpdatePropertyPayload extends Partial<CreatePropertyPayload> {}

interface MyPropertiesResponse {
  status: string;
  results: number;
  totalPages?: number;
  currentPage?: number;
  data: {
    properties: Property[];
  };
}

interface RecommendationsResponse {
  status: string;
  results: number;
  data: {
    properties: Property[];
  };
}

export const propertyService = {
  async getAllProperties(filters?: PropertyFilters) {
    const query = buildPropertiesQuery(filters);
    const response = await requestJson<PropertiesResponse>(`/properties${query}`, {
      method: "GET",
    });

    return {
      ...response,
      data: {
        properties: applyClientSideKeywordFilter(response.data.properties, filters),
      },
    };
  },

  async getPropertyById(id: string) {
    const response = await requestJson<PropertyResponse>(`/properties/${id}`, {
      method: "GET",
    });
    return response.data.property;
  },

  async createProperty(data: CreatePropertyPayload) {
    const response = await requestJson<PropertyResponse>("/properties", {
      method: "POST",
      body: JSON.stringify(data),
    });
    return response.data.property;
  },

  async updateProperty(id: string, data: UpdatePropertyPayload) {
    const response = await requestJson<PropertyResponse>(`/properties/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
    return response.data.property;
  },

  async deleteProperty(id: string) {
    return requestJson(`/properties/${id}`, {
      method: "DELETE",
    });
  },

  async getMyProperties(filters?: PropertyFilters) {
    const query = buildPropertiesQuery(filters);
    const response = await requestJson<MyPropertiesResponse>(`/properties${query}`, {
      method: "GET",
    });
    return response.data.properties;
  },

  async getRecommendations(propertyId: string) {
    const response = await requestJson<RecommendationsResponse>(`/properties/${propertyId}/recommendations`, {
      method: "GET",
    });
    return response.data.properties;
  },

  async getPropertiesWithin(distance: number, lat: number, lng: number, unit: "km" | "mi" = "km") {
    const latlng = `${lat},${lng}`;
    const response = await requestJson<PropertiesResponse>(
      `/properties/properties-within/${distance}/center/${latlng}/unit/${unit}`,
      { method: "GET" }
    );
    return response.data.properties;
  },
};

export default propertyService;

