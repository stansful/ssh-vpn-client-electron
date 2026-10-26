import { readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The app's version, for the release scripts (scripts/make-release.sh,
 * scripts/build-release.sh, .github/scripts/*.sh). It is "version" in
 * package.json, and npm keeps two copies of it in package-lock.json
 * ("version" and packages[""].version) that `npm ci` never checks.
 *
 *   node scripts/lib/package-version.mjs get          prints package.json's version
 *   node scripts/lib/package-version.mjs check        fails when package-lock.json says another one
 *   node scripts/lib/package-version.mjs set X.Y.Z    writes X.Y.Z to all three
 *
 * `set` keeps each file byte for byte apart from those lines: it refuses a file
 * that npm would not have written that way (indent, line ends, final newline),
 * so the release commit never reformats anything. Messages are in Russian, as
 * the release scripts' are.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
// Same as VERSION_RE in scripts/lib/version.sh: X.Y.Z without leading zeros.
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;

const [command, ...rest] = process.argv.slice(2);
try {
  if (command === "get" && rest.length === 0) {
    console.log(readJson("package.json").data.version ?? "");
  } else if (command === "check" && rest.length === 0) {
    check();
  } else if (command === "set" && rest.length === 1) {
    set(rest[0]);
  } else {
    fail("использование: node scripts/lib/package-version.mjs get | check | set X.Y.Z", 2);
  }
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}

function check() {
  const { version } = readJson("package.json").data;
  const lock = readJson("package-lock.json").data;
  const found = [lock.version, lock.packages?.[""]?.version];
  if (found.some((value) => value !== version)) {
    fail(
      `в package-lock.json версия ${found.map(String).join(" / ")}, а в package.json ${version}. ` +
        "Выровняйте их: scripts/make-release.sh или npm install --package-lock-only."
    );
  }
}

function set(version) {
  if (!versionPattern.test(version)) {
    fail(`«${version}» — не версия X.Y.Z (три числа без ведущих нулей, без «v»).`);
  }
  const files = ["package.json", "package-lock.json"].map(readJson);
  for (const file of files) {
    if (file.format(file.data) !== file.text) {
      // npm pkg rewrites package.json, npm install --package-lock-only the lock, both the way npm lays them out
      const resave =
        file.name === "package.json"
          ? `npm pkg set version=${file.data.version}`
          : "npm install --package-lock-only";
      fail(
        `${file.name} записан не так, как его пишет npm (например, массив или объект в одну строку, лишние ` +
          "пробелы, экранирование), а релизный коммит меняет в нём только версию. Пересохраните его через " +
          `${resave} и закоммитьте.`
      );
    }
  }
  const [pkg, lock] = files;
  pkg.data.version = version;
  lock.data.version = version;
  if (lock.data.packages?.[""]) {
    lock.data.packages[""].version = version;
  }
  // Both files are checked before either is written; a temp file and a rename
  // never leave a half-written one behind.
  for (const file of files) {
    const target = path.join(root, file.name);
    writeFileSync(`${target}.tmp`, file.format(file.data));
    renameSync(`${target}.tmp`, target);
  }
}

function readJson(name) {
  let text;
  try {
    text = readFileSync(path.join(root, name), "utf8");
  } catch (error) {
    throw new Error(`не удалось прочитать ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch (error) {
    throw new Error(`${name} — не JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  // How npm writes it: the first line's indent, CRLF when the file has it, and
  // the final newline when there is one.
  const indent = /^\{\r?\n([ \t]+)"/u.exec(text)?.[1] ?? "  ";
  const newline = text.includes("\r\n") ? "\r\n" : "\n";
  const eof = text.endsWith(newline) ? newline : "";
  const format = (value) => JSON.stringify(value, null, indent).replace(/\n/gu, newline) + eof;
  return { name, text, data, format };
}

function fail(message, code = 1) {
  console.error(`Ошибка: ${message}`);
  process.exit(code);
}
