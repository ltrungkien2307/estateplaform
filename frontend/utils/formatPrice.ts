/**
 * Formats a price number into a short Vietnamese currency string.
 * Example: 45000000000 -> "45 tỷ"
 * Example: 120000000 -> "120 tr"
 */
export function formatVNDShort(price: number): string {
  if (!price || isNaN(price)) return "—";

  if (price >= 1_000_000_000) {
    const bill = price / 1_000_000_000;
    // If it's a whole number, don't show decimal
    const formatted = bill % 1 === 0 ? bill.toFixed(0) : bill.toFixed(1);
    return `${formatted.replace('.', ',')} tỷ`;
  }
  
  if (price >= 1_000_000) {
    const mill = price / 1_000_000;
    const formatted = mill % 1 === 0 ? mill.toFixed(0) : mill.toFixed(1);
    return `${formatted.replace('.', ',')} tr`;
  }

  return new Intl.NumberFormat("vi-VN").format(price) + " đ";
}

/**
 * Calculates and formats price per square meter.
 */
export function formatPricePerSqm(price: number, area: number): string | null {
  if (!price || !area || area <= 0) return null;
  const perSqm = Math.round(price / area);
  
  if (perSqm >= 1_000_000) {
    return (perSqm / 1_000_000).toFixed(1).replace('.', ',') + " tr/m²";
  }
  
  return new Intl.NumberFormat("vi-VN").format(perSqm) + " đ/m²";
}
