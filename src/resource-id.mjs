// Stage 8: Separate resource identifiers by resource type.

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const RESOURCE_TYPES = Object.freeze({
  NOTE: 'notes',
  ANNOUNCEMENT: 'announcements',
});

export function createResourceId(type, id) {
  if (!Object.values(RESOURCE_TYPES).includes(type)) {
    throw new TypeError('INVALID_RESOURCE_TYPE');
  }

  if (typeof id !== 'string' || !UUID_PATTERN.test(id)) {
    throw new TypeError('INVALID_RESOURCE_ID');
  }

  return `${type}/${id.toLowerCase()}`;
}

export function parseResourceId(resourceId) {
  if (typeof resourceId !== 'string') {
    return null;
  }

  const parts = resourceId.split('/');

  if (parts.length !== 2) {
    return null;
  }

  const [type, id] = parts;

  if (
    !Object.values(RESOURCE_TYPES).includes(type) ||
    !UUID_PATTERN.test(id)
  ) {
    return null;
  }

  return {
    type,
    id: id.toLowerCase(),
  };
}