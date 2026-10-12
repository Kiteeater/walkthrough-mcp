// Order pricing. Legacy orders were migrated before line items existed and carry `legacyTotal` instead.
function orderTotal(order) {
  return order.items.reduce((sum, item) => sum + item.price * item.qty, 0);
}

module.exports = { orderTotal };
