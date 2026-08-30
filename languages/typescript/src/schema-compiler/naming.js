/** Stable bounded SQL names. FNV-1a is only a name function, never an integrity hash.
 * The validator separately rejects all generated-name collisions before emission.
 */
export function constraintName(storage, kind, identity) {
  const source = JSON.stringify(["ores.schema-ir.v1", storage.schema, storage.table, kind, identity]);
  let hash = 0xcbf29ce484222325n;
  for (const character of source) {
    hash = BigInt.asUintN(64, (hash ^ BigInt(character.codePointAt(0))) * 0x100000001b3n);
  }
  return `ores_ir_${kind}_${hash.toString(16).padStart(16, "0")}`;
}

export function foreignIdentity(key, target) {
  return [key.fields, target.schema, target.table, key.references.fields];
}
