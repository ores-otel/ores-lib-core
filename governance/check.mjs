#!/usr/bin/env node
import { lstat, readFile, readdir } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const fail = (message) => { console.error(`[governance] ${message}`); process.exitCode = 1; };
const expectedValidatorRevision = 'bd503465dab8c5148fee722b443ed04ff126c9bf';

function within(base, target) {
  const r = relative(base, target);
  return r === '' || (!r.startsWith(`..${sep}`) && r !== '..' && !isAbsolute(r));
}
function repoPath(value, label) {
  if (typeof value !== 'string' || !value || value.includes('\0') || isAbsolute(value)) throw new Error(`${label} must be repository-relative`);
  const absolute = resolve(root, value);
  if (!within(root, absolute)) throw new Error(`${label} escapes repository root`);
  return absolute;
}
async function realFile(value, label) {
  const absolute = repoPath(value, label);
  const st = await lstat(absolute);
  if (st.isSymbolicLink() || !st.isFile()) throw new Error(`${label} must be a real file: ${value}`);
  return absolute;
}
async function realDirectory(value, label) {
  const absolute = repoPath(value, label);
  const st = await lstat(absolute);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`${label} must be a real directory: ${value}`);
  return absolute;
}
function parseZpkg(source) {
  const targets = new Map();
  const dependencies = new Map();
  let section = '';
  for (const raw of source.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const sectionMatch = line.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) { section = sectionMatch[1]; continue; }
    if (section === 'dependencies') {
      const m = line.match(/^"([^"]+)"\s*=\s*"([^"]+)"$/);
      if (m) dependencies.set(m[1], m[2]);
      continue;
    }
    const target = section.match(/^targets\.([A-Za-z0-9_-]+)$/)?.[1];
    if (!target) continue;
    const dir = line.match(/^dir\s*=\s*"([^"]+)"$/)?.[1];
    if (dir) {
      if (targets.has(target)) throw new Error(`duplicate package target: ${target}`);
      targets.set(target, dir);
    }
  }
  return { targets, dependencies };
}

try {
  const langsRoot = await realDirectory('langs', 'runtime language root');
  const runtimeLanguages = [];
  for (const entry of (await readdir(langsRoot, { withFileTypes: true })).sort((a,b) => a.name.localeCompare(b.name))) {
    if (entry.isSymbolicLink() || !entry.isDirectory()) throw new Error(`langs/ may contain only real runtime-language directories: ${entry.name}`);
    runtimeLanguages.push(entry.name);
  }
  if (!runtimeLanguages.length) throw new Error('runtime language set is empty');

  await realDirectory('languages/typescript', 'schema compiler tooling lane');
  await realDirectory('admin-orm', 'admin ORM lane');
  await realDirectory('database/postgres', 'postgres lane');

  const zpkg = parseZpkg(await readFile(await realFile('.zpkg.toml', 'Zed manifest'), 'utf8'));
  const runtimeTargetDirs = [...zpkg.targets.values()].filter((dir) => dir.startsWith('langs/')).sort();
  const expectedRuntimeDirs = runtimeLanguages.map((language) => `langs/${language}`).sort();
  const missingRuntimeTargets = expectedRuntimeDirs.filter((dir) => !runtimeTargetDirs.includes(dir));
  const staleRuntimeTargets = runtimeTargetDirs.filter((dir) => !expectedRuntimeDirs.includes(dir));
  if (missingRuntimeTargets.length || staleRuntimeTargets.length) throw new Error(`runtime/Zed drift; missing=${missingRuntimeTargets.join(',')} stale=${staleRuntimeTargets.join(',')}`);
  if (new Set(runtimeTargetDirs).size !== runtimeTargetDirs.length) throw new Error('multiple Zed targets point at one runtime directory');
  if (zpkg.targets.get('postgres') !== 'database/postgres') throw new Error('Postgres target must remain database/postgres');
  if ([...zpkg.targets.values()].includes('admin-orm')) throw new Error('admin-orm is private/server-only and must not be a public Zed target');
  if ([...zpkg.targets.values()].some((dir) => dir.startsWith('languages/'))) throw new Error('schema/compiler tooling under languages/ must not masquerade as a runtime package target');

  const dependencies = JSON.parse(await readFile(await realFile('contracts/dependencies.json', 'dependency contract'), 'utf8'));
  if (dependencies.schema !== 'ores.lib-core.dependencies/v1' || !Array.isArray(dependencies.dependencies)) throw new Error('invalid dependency contract');
  if (dependencies.globalProviderInstallationAllowed !== false || dependencies.rawBiometricMaterialAllowed !== false) throw new Error('unsafe dependency/security policy');
  const contractDeps = new Map();
  for (const dep of dependencies.dependencies) {
    if (!dep || typeof dep.package !== 'string' || typeof dep.requirement !== 'string' || contractDeps.has(dep.package)) throw new Error(`invalid/duplicate dependency contract entry: ${dep?.package}`);
    contractDeps.set(dep.package, dep.requirement);
  }
  const missingDependencyContracts = [...zpkg.dependencies].filter(([name, requirement]) => contractDeps.get(name) !== requirement).map(([name]) => name);
  const staleDependencyContracts = [...contractDeps].filter(([name, requirement]) => zpkg.dependencies.get(name) !== requirement).map(([name]) => name);
  if (missingDependencyContracts.length || staleDependencyContracts.length) throw new Error(`dependency contract/Zed drift; missing=${missingDependencyContracts.join(',')} stale=${staleDependencyContracts.join(',')}`);

  const admission = JSON.parse(await readFile(await realFile('contract-admission/contract-ir-consumer.json', 'contract admission manifest'), 'utf8'));
  if (admission.schema !== 'ores.contract-ir-consumer/v1' || admission.repository !== 'ores-otel/ores-lib-core' || admission.repositoryRole !== 'lib-core') throw new Error('invalid contract admission identity');
  if (admission.canonicalAuthorityRepository !== 'ores-otel/ores-interfaces') throw new Error('canonical contract authority drift');
  if (admission.validator?.repository !== 'ORESoftware/typespec-json-schema-validator' || admission.validator?.actionCommit !== expectedValidatorRevision) throw new Error('validator provenance drift');
  if (admission.authorityModel?.precedence !== 'none' || admission.admission?.allowFallbackAuthority !== false) throw new Error('unsafe contract authority fallback/precedence');
  for (const key of ['requirePassedReceipt','requireAdmissibleContractIr','requireZeroUnexplainedFindings','rejectEditableAuthority']) if (admission.admission?.[key] !== true) throw new Error(`contract admission must fail closed: ${key}`);

  const conformance = JSON.parse(await readFile(await realFile('conformance/manifest.v1.json', 'conformance manifest'), 'utf8'));
  if (conformance.repository !== 'ores-otel/ores-lib-core') throw new Error('conformance repository identity drift');
  const runtimeSet = new Set(runtimeLanguages);
  for (const participant of conformance.requiredParticipants ?? []) {
    if (!participant || typeof participant.id !== 'string' || !runtimeSet.has(participant.id)) throw new Error(`unknown required runtime conformance participant: ${participant?.id}`);
  }

  console.log(JSON.stringify({
    schema: 'ores.governance.lib-core-check/v1',
    repository: 'ores-otel/ores-lib-core',
    runtime_languages: runtimeLanguages,
    runtime_zpkg_targets: [...zpkg.targets].filter(([,dir]) => dir.startsWith('langs/')).map(([name]) => name).sort(),
    tooling_lane: 'languages/typescript',
    private_lane: 'admin-orm',
    database_lane: 'database/postgres',
    dependencies: [...contractDeps.keys()].sort(),
    validator_revision: admission.validator.actionCommit
  }, null, 2));
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
