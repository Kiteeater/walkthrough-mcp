/**
 * Recursively Object.freeze plain data (arrays, plain objects) and return it with its type unchanged. Used for
 * security-relevant public constants (connector presets, default alert patterns) so a caller holding the exported
 * object cannot widen core policy at runtime. Callers that need a variant copy it ({ ...c, ... }).
 */
export function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value as object)) deepFreeze(v);
  }
  return value;
}
