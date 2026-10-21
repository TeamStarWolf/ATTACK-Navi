// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// A tiny, dependency-free JSON Schema (draft-07) validator covering exactly the
// keywords the Lylat consumer schema uses: type, const, enum, pattern, format
// (date / date-time), additionalProperties:false, required, properties, items,
// minItems, $ref (local #/definitions/*), and allOf with if/then. It is NOT a
// general draft-07 implementation; it exists so the CI check can validate the
// fixture and reject the invalid corpus without pulling ajv into the repo.
//
// It mirrors src/app/contracts/lylat-validated-detections.ts: the two must agree
// on the same corpus, which the CI check and the unit spec both assert.

const DATE_ONLY = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;
const DATE_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$/;

function isObj(x) {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function typeOf(x) {
  if (x === null) return 'null';
  if (Array.isArray(x)) return 'array';
  return typeof x; // 'object' | 'string' | 'number' | 'boolean'
}

function resolveRef(ref, root) {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) {
    throw new Error(`unsupported $ref: ${ref}`);
  }
  let node = root;
  for (const part of ref.slice(2).split('/')) {
    node = node?.[part];
    if (node === undefined) throw new Error(`$ref not found: ${ref}`);
  }
  return node;
}

function validateDate(value) {
  if (!DATE_ONLY.test(value)) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

function validateDateTime(value) {
  return DATE_TIME.test(value) && !Number.isNaN(Date.parse(value));
}

function check(schema, value, path, root, errors) {
  if (schema.$ref !== undefined) {
    check(resolveRef(schema.$ref, root), value, path, root, errors);
    return;
  }

  if (schema.type !== undefined) {
    const t = typeOf(value);
    const want = t === 'number' && Number.isInteger(value) && schema.type === 'integer' ? 'integer' : t;
    if (want !== schema.type && !(schema.type === 'number' && t === 'number')) {
      errors.push(`${path}: expected type ${schema.type}, got ${t}`);
      return; // a wrong type makes the rest meaningless
    }
  }

  if (schema.const !== undefined && value !== schema.const) {
    errors.push(`${path}: must equal ${JSON.stringify(schema.const)}`);
  }

  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
    errors.push(`${path}: not one of ${schema.enum.join(', ')}`);
  }

  if (typeof value === 'string') {
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${path}: does not match ${schema.pattern}`);
    }
    if (schema.format === 'date' && !validateDate(value)) {
      errors.push(`${path}: not a valid date`);
    }
    if (schema.format === 'date-time' && !validateDateTime(value)) {
      errors.push(`${path}: not a valid date-time`);
    }
  }

  if (isObj(value) && (schema.properties || schema.required || schema.additionalProperties === false)) {
    const props = schema.properties ?? {};
    for (const key of schema.required ?? []) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) {
        errors.push(`${path}: missing required property "${key}"`);
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(props, key)) {
          errors.push(`${path}: unexpected property "${key}"`);
        }
      }
    }
    for (const [key, sub] of Object.entries(props)) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        check(sub, value[key], `${path}/${key}`, root, errors);
      }
    }
  }

  if (Array.isArray(value)) {
    if (typeof schema.minItems === 'number' && value.length < schema.minItems) {
      errors.push(`${path}: fewer than ${schema.minItems} items`);
    }
    if (schema.items) {
      value.forEach((item, i) => check(schema.items, item, `${path}[${i}]`, root, errors));
    }
  }

  for (const sub of schema.allOf ?? []) {
    if (sub.if !== undefined) {
      const condErrors = [];
      check(sub.if, value, path, root, condErrors);
      if (condErrors.length === 0 && sub.then !== undefined) {
        check(sub.then, value, path, root, errors);
      } else if (condErrors.length > 0 && sub.else !== undefined) {
        check(sub.else, value, path, root, errors);
      }
    } else {
      check(sub, value, path, root, errors);
    }
  }
}

/** Validate `instance` against `schema`. Returns a (possibly empty) list of error strings. */
export function validate(schema, instance) {
  const errors = [];
  check(schema, instance, '#', schema, errors);
  return errors;
}
