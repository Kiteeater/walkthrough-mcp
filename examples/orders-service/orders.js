// In-memory order store. Order 3 is a legacy record migrated before line items existed.
const ORDERS = [
  { id: 1, customer: "ada", items: [{ sku: "pen", price: 2.5, qty: 4 }] },
  { id: 2, customer: "lin", items: [{ sku: "ink", price: 7, qty: 1 }, { sku: "pad", price: 3, qty: 2 }] },
  { id: 3, customer: "kai", legacyTotal: 12 },
];

function orderTotal(order) {
  return order.items.reduce((sum, item) => sum + item.price * item.qty, 0);
}

function listOrders() {
  return ORDERS.map((o) => ({ id: o.id, customer: o.customer, total: orderTotal(o) }));
}

function getOrder(id) {
  const o = ORDERS.find((x) => x.id === id);
  return o ? { id: o.id, customer: o.customer, items: o.items ?? [] } : undefined;
}

module.exports = { listOrders, getOrder };
