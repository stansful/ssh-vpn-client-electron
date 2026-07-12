import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default [
  {
    ignores: ["dist/**", "release/**", "coverage/**", "node_modules/**"]
  },
  js.configs.recommended,
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: {
      globals: {
        console: "readonly",
        process: "readonly"
      }
    }
  },
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx,mts,cts}"],
    languageOptions: {
      parserOptions: {
        project: ["./tsconfig.json", "./tsconfig.node.json"],
        tsconfigRootDir: import.meta.dirname
      }
    },
    rules: {
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/consistent-type-imports": "error"
    }
  }
];
