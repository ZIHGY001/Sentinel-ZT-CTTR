export function parseIndicators(text) {
  const value = JSON.parse(text);
  const rows = Array.isArray(value) ? value : value?.indicators;
  if (!Array.isArray(rows) || rows.length > 10000 ||
      rows.some(row => !row || typeof row !== 'object' || Array.isArray(row))) {
    throw new Error('IOC 文件必须是对象数组，或包含 indicators 数组的对象，最多 10000 条。');
  }
  return rows;
}
